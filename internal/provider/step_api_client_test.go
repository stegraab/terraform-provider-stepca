package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestBuildCSRFromPrivateKeyPEM(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	csrPEM, err := buildCSRFromPrivateKeyPEM("ca.example.internal", []string{"ca.example.internal", "10.0.0.1"}, privateKeyPEM)
	if err != nil {
		t.Fatalf("buildCSRFromPrivateKeyPEM returned error: %v", err)
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

func TestParsePrivateKeyPEM(t *testing.T) {
	t.Parallel()

	if _, err := parsePrivateKeyPEM("not a key"); err == nil {
		t.Fatal("expected error for invalid PEM")
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
