package provider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	stepToken "github.com/smallstep/cli-utils/token"
	stepProvision "github.com/smallstep/cli-utils/token/provision"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/randutil"
)

type authMode string

const (
	authModeToken authMode = "token"
	authModeJWK   authMode = "jwk"
)

const adminIssuer = "step-admin-client/1.0"

type stepAPIClient struct {
	baseURL          string
	httpClient       *http.Client
	authMode         authMode
	token            string
	adminProvisioner string
	adminSubject     string
	adminPassword    string

	mu                sync.Mutex
	adminSigner       crypto.Signer
	adminSignerAlg    string
	adminX5CCertChain []string
	adminCertExpiry   time.Time
}

type issueCertificateRequest struct {
	CommonName          string
	SANs                []string
	Provisioner         string
	ProvisionerPassword string
	PrivateKeyPEM       string
	NotAfter            string
}

type issuedCertificate struct {
	LeafPEM      string
	CertChainPEM string
	CaPEM        string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber string
}

type apiStatusError struct {
	StatusCode int
	Body       string
}

func (e *apiStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("admin API request failed with status %d", e.StatusCode)
	}
	return fmt.Sprintf("admin API request failed with status %d: %s", e.StatusCode, e.Body)
}

func (c *stepAPIClient) getProvisioner(ctx context.Context, name string) (map[string]any, bool, error) {
	body, err := c.requestAdmin(ctx, http.MethodGet, "/provisioners/"+url.PathEscape(name), nil)
	if err != nil {
		var statusErr *apiStatusError
		if ok := asStatusError(err, &statusErr); ok && statusErr.StatusCode == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, err
	}

	var provisioner map[string]any
	if err := json.Unmarshal(body, &provisioner); err != nil {
		return nil, false, fmt.Errorf("decode provisioner response: %w", err)
	}

	return provisioner, true, nil
}

func (c *stepAPIClient) createProvisioner(ctx context.Context, payload map[string]any) error {
	_, err := c.requestAdmin(ctx, http.MethodPost, "/provisioners", payload)
	return err
}

func (c *stepAPIClient) updateProvisioner(ctx context.Context, name string, payload map[string]any) error {
	_, err := c.requestAdmin(ctx, http.MethodPut, "/provisioners/"+url.PathEscape(name), payload)
	return err
}

func (c *stepAPIClient) deleteProvisioner(ctx context.Context, name string) error {
	_, err := c.requestAdmin(ctx, http.MethodDelete, "/provisioners/"+url.PathEscape(name), nil)
	if err != nil {
		var statusErr *apiStatusError
		if ok := asStatusError(err, &statusErr); ok && statusErr.StatusCode == http.StatusNotFound {
			return nil
		}
	}
	return err
}

func (c *stepAPIClient) requestAdmin(ctx context.Context, method string, path string, payload map[string]any) ([]byte, error) {
	fullURL := c.baseURL + "/admin" + path
	authHeader, err := c.adminAuthHeader(ctx, fullURL)
	if err != nil {
		return nil, err
	}
	body, err := c.requestWithAuth(ctx, method, fullURL, payload, authHeader)
	if err != nil {
		var statusErr *apiStatusError
		if asStatusError(err, &statusErr) && statusErr.StatusCode == http.StatusUnauthorized && c.authMode == authModeJWK {
			return nil, fmt.Errorf(
				"%w (JWK admin auth failed; ensure an admin exists for subject %q under provisioner %q, for example: step ca admin add %q --provisioner %q)",
				err,
				c.adminSubject,
				c.adminProvisioner,
				c.adminSubject,
				c.adminProvisioner,
			)
		}
		return nil, err
	}
	return body, nil
}

func (c *stepAPIClient) requestPublic(ctx context.Context, method string, path string, payload map[string]any) ([]byte, error) {
	fullURL := c.baseURL + path
	return c.requestWithAuth(ctx, method, fullURL, payload, "")
}

func (c *stepAPIClient) requestWithAuth(ctx context.Context, method string, fullURL string, payload map[string]any, authHeader string) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("perform request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &apiStatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}

	return body, nil
}

func (c *stepAPIClient) adminAuthHeader(ctx context.Context, audienceURL string) (string, error) {
	switch c.authMode {
	case authModeToken:
		tok := strings.TrimSpace(c.token)
		if tok == "" {
			return "", fmt.Errorf("token auth selected but token is empty")
		}
		return tok, nil
	case authModeJWK:
		if err := c.ensureAdminIdentity(ctx); err != nil {
			return "", err
		}
		return c.generateAdminJWT(audienceURL)
	default:
		return "", fmt.Errorf("unsupported auth mode: %s", c.authMode)
	}
}

func (c *stepAPIClient) ensureAdminIdentity(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.adminSigner != nil && time.Until(c.adminCertExpiry) > 5*time.Minute {
		return nil
	}

	kid, err := c.lookupJWKProvisionerKID(ctx)
	if err != nil {
		return err
	}

	encryptedKey, err := c.getEncryptedProvisionerKey(ctx, kid)
	if err != nil {
		return err
	}

	jwk, err := decryptProvisionerJWK(encryptedKey, c.adminPassword)
	if err != nil {
		return err
	}

	ott, err := c.generateProvisionerSignToken(jwk, kid)
	if err != nil {
		return err
	}

	adminKey, csrPEM, err := generateAdminCSR(c.adminSubject)
	if err != nil {
		return err
	}

	signResp, err := c.signAdminCSR(ctx, csrPEM, ott)
	if err != nil {
		return err
	}

	certChain, certChainB64, certExpiry, err := parseCertChain(signResp)
	if err != nil {
		return err
	}

	signerAlg, err := signingAlgorithmForKey(adminKey)
	if err != nil {
		return err
	}

	c.adminSigner = adminKey
	c.adminSignerAlg = signerAlg
	c.adminX5CCertChain = certChainB64
	c.adminCertExpiry = certExpiry

	_ = certChain
	return nil
}

func (c *stepAPIClient) lookupJWKProvisionerKID(ctx context.Context) (string, error) {
	return c.lookupJWKProvisionerKIDByName(ctx, c.adminProvisioner)
}

func (c *stepAPIClient) lookupJWKProvisionerKIDByName(ctx context.Context, provisionerName string) (string, error) {
	body, err := c.requestPublic(ctx, http.MethodGet, "/provisioners", nil)
	if err != nil {
		return "", fmt.Errorf("list provisioners: %w", err)
	}

	var payload struct {
		Provisioners []map[string]any `json:"provisioners"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode provisioners response: %w", err)
	}

	for _, p := range payload.Provisioners {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		if name != provisionerName || strings.ToUpper(typ) != "JWK" {
			continue
		}

		keyObj, ok := p["key"].(map[string]any)
		if !ok {
			return "", fmt.Errorf("provisioner %q is missing key object", provisionerName)
		}
		kid, _ := keyObj["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			return "", fmt.Errorf("provisioner %q key is missing kid", provisionerName)
		}
		return kid, nil
	}

	return "", fmt.Errorf("JWK provisioner %q not found", provisionerName)
}

func (c *stepAPIClient) getEncryptedProvisionerKey(ctx context.Context, kid string) (string, error) {
	body, err := c.requestPublic(ctx, http.MethodGet, "/provisioners/"+url.PathEscape(kid)+"/encrypted-key", nil)
	if err != nil {
		return "", fmt.Errorf("get encrypted provisioner key: %w", err)
	}

	var payload struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode encrypted key response: %w", err)
	}
	if strings.TrimSpace(payload.Key) == "" {
		return "", fmt.Errorf("encrypted key response did not include key")
	}
	return payload.Key, nil
}

func decryptProvisionerJWK(encryptedKey string, password string) (*jose.JSONWebKey, error) {
	decrypted, err := jose.Decrypt([]byte(encryptedKey), jose.WithPassword([]byte(password)))
	if err != nil {
		return nil, fmt.Errorf("decrypt provisioner key: %w", err)
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(decrypted, &jwk); err != nil {
		return nil, fmt.Errorf("decode decrypted JWK: %w", err)
	}

	if jwk.Key == nil {
		return nil, fmt.Errorf("decrypted JWK did not contain private key")
	}

	return &jwk, nil
}

func (c *stepAPIClient) generateProvisionerSignToken(jwk *jose.JSONWebKey, kid string) (string, error) {
	return c.generateProvisionerSignTokenWithClaims(
		jwk,
		kid,
		c.adminProvisioner,
		c.adminSubject,
		[]string{c.adminSubject},
	)
}

func (c *stepAPIClient) generateProvisionerSignTokenWithClaims(
	jwk *jose.JSONWebKey,
	kid string,
	provisioner string,
	subject string,
	sans []string,
) (string, error) {
	aud := c.baseURL + "/1.0/sign"
	now := time.Now().UTC()

	jwtID, err := randutil.Hex(64)
	if err != nil {
		return "", fmt.Errorf("generate jwt id: %w", err)
	}

	tokOptions := []stepToken.Options{
		stepToken.WithJWTID(jwtID),
		stepToken.WithKid(kid),
		stepToken.WithIssuer(provisioner),
		stepToken.WithAudience(aud),
		stepToken.WithValidity(now, now.Add(stepToken.DefaultValidity)),
		stepToken.WithSANS(sans),
	}

	tok, err := stepProvision.New(subject, tokOptions...)
	if err != nil {
		return "", fmt.Errorf("create provisioning token: %w", err)
	}

	alg := jwk.Algorithm
	if alg == "" {
		alg, err = signingAlgorithmForKey(jwk.Key)
		if err != nil {
			return "", err
		}
	}

	signed, err := tok.SignedString(alg, jwk.Key)
	if err != nil {
		return "", fmt.Errorf("sign provisioning token: %w", err)
	}
	return signed, nil
}

func (c *stepAPIClient) issueCertificate(ctx context.Context, req issueCertificateRequest) (*issuedCertificate, error) {
	kid, err := c.lookupJWKProvisionerKIDByName(ctx, req.Provisioner)
	if err != nil {
		return nil, err
	}

	encryptedKey, err := c.getEncryptedProvisionerKey(ctx, kid)
	if err != nil {
		return nil, err
	}

	jwk, err := decryptProvisionerJWK(encryptedKey, req.ProvisionerPassword)
	if err != nil {
		return nil, err
	}

	sans := uniqueSANs(append([]string{req.CommonName}, req.SANs...))
	ott, err := c.generateProvisionerSignTokenWithClaims(jwk, kid, req.Provisioner, req.CommonName, sans)
	if err != nil {
		return nil, err
	}

	csrPEM, err := buildCSRFromPrivateKeyPEM(req.CommonName, sans, req.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	signReq := map[string]any{
		"csr": csrPEM,
		"ott": ott,
	}
	if strings.TrimSpace(req.NotAfter) != "" {
		signReq["notAfter"] = strings.TrimSpace(req.NotAfter)
	}

	signResp, err := c.signCSR(ctx, signReq)
	if err != nil {
		return nil, err
	}

	certPEMs, err := certChainStrings(signResp)
	if err != nil {
		return nil, err
	}
	leaf, err := parsePEMCertificate(certPEMs[0])
	if err != nil {
		return nil, err
	}

	return &issuedCertificate{
		LeafPEM:      certPEMs[0],
		CertChainPEM: strings.Join(certPEMs, "\n"),
		CaPEM:        strings.Join(certPEMs[1:], "\n"),
		NotBefore:    leaf.NotBefore,
		NotAfter:     leaf.NotAfter,
		SerialNumber: leaf.SerialNumber.String(),
	}, nil
}

func generateAdminCSR(subject string) (crypto.Signer, string, error) {
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate admin private key: %w", err)
	}

	dnsNames, ips, emails, uris := splitSANs([]string{subject})
	tpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: subject},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, adminKey)
	if err != nil {
		return nil, "", fmt.Errorf("create certificate request: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return adminKey, string(csrPEM), nil
}

func buildCSRFromPrivateKeyPEM(commonName string, sans []string, privateKeyPEM string) (string, error) {
	leafKey, err := parsePrivateKeyPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}
	dnsNames, ips, emails, uris := splitSANs(sans)
	tpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: commonName},
		DNSNames:       dnsNames,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tpl, leafKey)
	if err != nil {
		return "", fmt.Errorf("create leaf certificate request: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return string(csrPEM), nil
}

func parsePrivateKeyPEM(privateKeyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("decode private key PEM: missing PEM block")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", key)
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("parse private key PEM: unsupported or invalid key format")
}

func splitSANs(sans []string) ([]string, []net.IP, []string, []*url.URL) {
	dnsNames := make([]string, 0, len(sans))
	ips := make([]net.IP, 0)
	emails := make([]string, 0)
	uris := make([]*url.URL, 0)

	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if u, err := url.Parse(san); err == nil && u.Scheme != "" {
			uris = append(uris, u)
			continue
		}
		if strings.Contains(san, "@") {
			emails = append(emails, san)
			continue
		}
		dnsNames = append(dnsNames, san)
	}

	return dnsNames, ips, emails, uris
}

func (c *stepAPIClient) signAdminCSR(ctx context.Context, csrPEM string, ott string) (map[string]any, error) {
	payload := map[string]any{
		"csr": csrPEM,
		"ott": ott,
	}

	response, err := c.signCSR(ctx, payload)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (c *stepAPIClient) signCSR(ctx context.Context, payload map[string]any) (map[string]any, error) {
	body, err := c.requestPublic(ctx, http.MethodPost, "/1.0/sign", payload)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode sign response: %w", err)
	}

	return response, nil
}

func parseCertChain(signResponse map[string]any) ([]*x509.Certificate, []string, time.Time, error) {
	certStrings, err := certChainStrings(signResponse)
	if err != nil {
		return nil, nil, time.Time{}, err
	}

	chain := make([]*x509.Certificate, 0, len(certStrings))
	chainB64 := make([]string, 0, len(certStrings))
	for _, certPEM := range certStrings {
		cert, err := parsePEMCertificate(certPEM)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		chain = append(chain, cert)
		chainB64 = append(chainB64, base64.StdEncoding.EncodeToString(cert.Raw))
	}

	leafExpiry := chain[0].NotAfter
	return chain, chainB64, leafExpiry, nil
}

func certChainStrings(signResponse map[string]any) ([]string, error) {
	certStrings := make([]string, 0)

	if chainRaw, ok := signResponse["certChain"].([]any); ok {
		for _, item := range chainRaw {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				certStrings = append(certStrings, s)
			}
		}
	}

	if len(certStrings) == 0 {
		if crt, ok := signResponse["crt"].(string); ok && strings.TrimSpace(crt) != "" {
			certStrings = append(certStrings, crt)
		}
	}

	if len(certStrings) == 0 {
		return nil, fmt.Errorf("sign response did not include certificate chain")
	}

	return certStrings, nil
}

func parsePEMCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("decode certificate PEM: missing PEM block")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("decode certificate PEM: unexpected block type %q", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func (c *stepAPIClient) generateAdminJWT(audienceURL string) (string, error) {
	jwtID, err := randutil.Hex(64)
	if err != nil {
		return "", fmt.Errorf("generate jwt id: %w", err)
	}

	aud := sanitizeAudience(audienceURL)
	now := time.Now().UTC()

	tokOptions := []stepToken.Options{
		stepToken.WithJWTID(jwtID),
		stepToken.WithIssuer(adminIssuer),
		stepToken.WithAudience(aud),
		stepToken.WithValidity(now, now.Add(stepToken.DefaultValidity)),
		stepToken.WithX5CCerts(c.adminX5CCertChain),
	}

	tok, err := stepProvision.New(c.adminSubject, tokOptions...)
	if err != nil {
		return "", fmt.Errorf("create admin token: %w", err)
	}

	signed, err := tok.SignedString(c.adminSignerAlg, c.adminSigner)
	if err != nil {
		return "", fmt.Errorf("sign admin token: %w", err)
	}
	return signed, nil
}

func sanitizeAudience(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func signingAlgorithmForKey(key interface{}) (string, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case *rsa.PrivateKey:
		return jose.DefaultRSASigAlgorithm, nil
	case ed25519.PrivateKey:
		return jose.EdDSA, nil
	case *jose.JSONWebKey:
		if k.Algorithm != "" {
			return k.Algorithm, nil
		}
		return signingAlgorithmForKey(k.Key)
	default:
		return "", fmt.Errorf("unsupported key type %T", key)
	}
}

func asStatusError(err error, target **apiStatusError) bool {
	if err == nil {
		return false
	}

	var typed *apiStatusError
	if !errors.As(err, &typed) {
		return false
	}
	*target = typed
	return true
}

func uniqueSANs(sans []string) []string {
	seen := make(map[string]struct{}, len(sans))
	out := make([]string, 0, len(sans))
	for _, san := range sans {
		s := strings.TrimSpace(san)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
