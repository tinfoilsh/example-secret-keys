package main

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"

	"github.com/tinfoilsh/tinfoil-go/verifier/attestation"
)

// decodeReport returns the raw SEV-SNP report bytes from a V2 document (base64 + gzip).
func decodeReport(doc *attestation.Document) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(doc.Body)
	if err != nil {
		return nil, fmt.Errorf("decoding report: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw)) // V2 reports are gzip-compressed
	if err != nil {
		return nil, fmt.Errorf("gunzip report: %w", err)
	}
	if raw, err = io.ReadAll(zr); err != nil {
		return nil, fmt.Errorf("gunzip report: %w", err)
	}
	return raw, nil
}

func parseReport(doc *attestation.Document) (*sevsnp.Report, error) {
	raw, err := decodeReport(doc)
	if err != nil {
		return nil, err
	}
	return abi.ReportToProto(raw)
}

// verifyReport checks a SEV-SNP report and returns its measurement and the
// 64-byte REPORTDATA the guest bound into it: the VCEK chains to the AMD root
// (ARK) via the ASK, and the report is signed by the VCEK. tinfoil-go
// hardcodes Genoa, so we verify here to support both Genoa (production) and
// Turin (box2); the product is taken from the report.
func verifyReport(doc *attestation.Document, vcekDER []byte) (measurement string, reportData []byte, err error) {
	raw, err := decodeReport(doc)
	if err != nil {
		return "", nil, err
	}
	report, err := abi.ReportToProto(raw)
	if err != nil {
		return "", nil, fmt.Errorf("parsing report: %w", err)
	}
	vcek, err := x509.ParseCertificate(vcekDER)
	if err != nil {
		return "", nil, fmt.Errorf("parsing vcek: %w", err)
	}
	ask, ark, err := amdChain(reportProduct(report))
	if err != nil {
		return "", nil, err
	}
	if err := ask.CheckSignatureFrom(ark); err != nil {
		return "", nil, fmt.Errorf("ASK not signed by ARK: %w", err)
	}
	if err := vcek.CheckSignatureFrom(ask); err != nil {
		return "", nil, fmt.Errorf("VCEK not signed by ASK: %w", err)
	}
	// Verify against the raw report bytes (fixed offsets) — go-sev-guest's proto
	// round-trip drops Turin (report v5) fields, breaking the signed component.
	if err := verify.SnpReportSignature(raw, vcek); err != nil {
		return "", nil, fmt.Errorf("report signature: %w", err)
	}
	rd := report.GetReportData()
	if len(rd) < 64 {
		return "", nil, fmt.Errorf("report data too short")
	}
	return hex.EncodeToString(report.GetMeasurement()), rd, nil
}

// reportProduct picks the AMD product line from the report's chip-ID shape:
// Turin uses an 8-byte ID (left-aligned, rest zero), Genoa/Milan a full 64 bytes.
func reportProduct(report *sevsnp.Report) sevsnp.SevProduct_SevProductName {
	if id := report.GetChipId(); len(id) == 64 && allZero(id[8:]) {
		return sevsnp.SevProduct_SEV_PRODUCT_TURIN
	}
	return sevsnp.SevProduct_SEV_PRODUCT_GENOA
}

// amdChain returns the (ASK, ARK) for a product from go-sev-guest's embedded,
// AMD-published VCEK CA bundles. We verify the chain ourselves (rather than via
// go-sev-guest's SnpAttestation) because it rejects the Turin FMC cert OID
// 1.3.6.1.4.1.3704.1.3.9 — but the trust anchors are the same ones it ships.
func amdChain(product sevsnp.SevProduct_SevProductName) (ask, ark *x509.Certificate, err error) {
	var chain []byte
	switch product {
	case sevsnp.SevProduct_SEV_PRODUCT_GENOA:
		chain = trust.AskArkGenoaVcekBytes
	case sevsnp.SevProduct_SEV_PRODUCT_TURIN:
		chain = trust.AskArkTurinVcekBytes
	default:
		return nil, nil, fmt.Errorf("no AMD cert chain for product %v", product)
	}
	var certs []*x509.Certificate
	for {
		var blk *pem.Block
		blk, chain = pem.Decode(chain)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing cert chain: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) != 2 {
		return nil, nil, fmt.Errorf("expected ASK+ARK, got %d certs", len(certs))
	}
	return certs[0], certs[1], nil // KDS cert_chain order: ASK, then ARK
}

// bundleVCEK returns the VCEK to verify a bundle with: the one the workload
// supplied, or — when it sent none (cmd/boot does not) — one fetched from KDS.
func bundleVCEK(b *attestation.Bundle) ([]byte, error) {
	if b.VCEK != "" {
		return base64.StdEncoding.DecodeString(b.VCEK)
	}
	return fetchVCEK(b.EnclaveAttestationReport)
}

// kdsProxyGetter fetches KDS objects through tinfoil's caching proxy rather than
// AMD's KDS directly. AMD's KDS rate-limits aggressively and go-sev-guest's
// default getter retries such failures indefinitely (no timeout) — which hangs
// the release. The proxy is cached and rate-limit-free; one attempt, bounded.
type kdsProxyGetter struct{ client *http.Client }

func (g kdsProxyGetter) Get(rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	u.Scheme, u.Host = "https", "kds-proxy.tinfoil.sh"
	resp, err := g.client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kds-proxy %s: %s", u.Path, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// fetchVCEK downloads the VCEK for a report's chip from KDS.
func fetchVCEK(doc *attestation.Document) ([]byte, error) {
	report, err := parseReport(doc)
	if err != nil {
		return nil, err
	}
	// Turin reports an 8-byte chip ID (left-aligned in the 64-byte field) and a
	// TCB layout with FMC inserted at byte 0 — both of which go-sev-guest v0.14.1
	// gets wrong (it zero-pads the chip ID and decodes the TCB with the old
	// layout, fetching a VCEK for the wrong TCB). Build the URL ourselves.
	if id := report.GetChipId(); len(id) == 64 && allZero(id[8:]) {
		return fetchTurinVCEK(id[:8], report.GetReportedTcb())
	}
	opts := verify.DefaultOptions()
	opts.Getter = kdsProxyGetter{client: &http.Client{Timeout: 15 * time.Second}}
	att, err := verify.GetAttestationFromReport(report, opts)
	if err != nil {
		return nil, fmt.Errorf("fetching VCEK from KDS: %w", err)
	}
	if att.GetCertificateChain().GetVcekCert() == nil {
		return nil, fmt.Errorf("KDS returned no VCEK")
	}
	return att.GetCertificateChain().GetVcekCert(), nil
}

// turinVCEKURL builds the KDS VCEK URL for a Turin chip from its 8-byte chip ID
// and reported TCB. Turin's TCB_VERSION bytes are [FMC, BL, TEE, SNP, _, _, _,
// MICROCODE] — the FMC byte at index 0 is the Turin addition go-sev-guest
// v0.14.1 doesn't know about.
func turinVCEKURL(chipID []byte, tcb uint64) string {
	return fmt.Sprintf(
		"https://kds-proxy.tinfoil.sh/vcek/v1/Turin/%x?fmcSPL=%d&blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		chipID, tcb&0xff, (tcb>>8)&0xff, (tcb>>16)&0xff, (tcb>>24)&0xff, (tcb>>56)&0xff)
}

func fetchTurinVCEK(chipID []byte, tcb uint64) ([]byte, error) {
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(turinVCEKURL(chipID, tcb))
	if err != nil {
		return nil, fmt.Errorf("fetching Turin VCEK: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Turin VCEK: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
