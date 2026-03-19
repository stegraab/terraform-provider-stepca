package provider

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestUniqueSANs(t *testing.T) {
	t.Parallel()

	in := []string{"  ca.example.internal  ", "10.0.0.1", "ca.example.internal", "", "10.0.0.1"}
	got := uniqueSANs(in)

	if len(got) != 2 {
		t.Fatalf("expected 2 SANs, got %d: %#v", len(got), got)
	}
	if got[0] != "ca.example.internal" {
		t.Fatalf("unexpected first SAN: %q", got[0])
	}
	if got[1] != "10.0.0.1" {
		t.Fatalf("unexpected second SAN: %q", got[1])
	}
}

func TestGenerateLeafCSR(t *testing.T) {
	t.Parallel()

	privateKeyPEM, csrPEM, err := generateLeafCSR("ca.example.internal", []string{"ca.example.internal", "10.0.0.1"})
	if err != nil {
		t.Fatalf("generateLeafCSR returned error: %v", err)
	}

	keyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatalf("expected PRIVATE KEY PEM block, got %#v", keyBlock)
	}
	if _, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("failed to parse PKCS8 private key: %v", err)
	}

	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected CERTIFICATE REQUEST PEM block, got %#v", csrBlock)
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	if csr.Subject.CommonName != "ca.example.internal" {
		t.Fatalf("unexpected common name: %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "ca.example.internal" {
		t.Fatalf("unexpected DNS SANs: %#v", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 1 || csr.IPAddresses[0].String() != "10.0.0.1" {
		t.Fatalf("unexpected IP SANs: %#v", csr.IPAddresses)
	}
}

func TestCertChainStrings(t *testing.T) {
	t.Parallel()

	t.Run("uses certChain when present", func(t *testing.T) {
		signResponse := map[string]any{
			"certChain": []any{"leaf", "intermediate"},
		}
		got, err := certChainStrings(signResponse)
		if err != nil {
			t.Fatalf("certChainStrings returned error: %v", err)
		}
		if len(got) != 2 || got[0] != "leaf" || got[1] != "intermediate" {
			t.Fatalf("unexpected chain: %#v", got)
		}
	})

	t.Run("falls back to crt", func(t *testing.T) {
		signResponse := map[string]any{
			"crt": "leaf-only",
		}
		got, err := certChainStrings(signResponse)
		if err != nil {
			t.Fatalf("certChainStrings returned error: %v", err)
		}
		if len(got) != 1 || got[0] != "leaf-only" {
			t.Fatalf("unexpected chain: %#v", got)
		}
	})

	t.Run("errors when empty", func(t *testing.T) {
		if _, err := certChainStrings(map[string]any{}); err == nil {
			t.Fatal("expected error for missing chain")
		}
	})
}
