package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.step.sm/crypto/jose"
)

func TestMachineEnrollmentClientLifecycle(t *testing.T) {
	t.Parallel()

	registration := machineEnrollment{
		ID:               "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		AttestorType:     "nutanix-vtpm",
		AttestorIdentity: "11111111-1111-4111-8111-111111111111",
		AttestorClaims: map[string]string{
			"generation_uuid": "22222222-2222-4222-8222-222222222222",
			"vtpm_disk_id":    "33333333-3333-4333-8333-333333333333",
		},
		MachineIdentity: "host/example.internal",
		SSHPrincipals:   []string{"example", "example.internal"},
		Status:          "pending",
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "local-development-token" {
			t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
		}
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/machine-enrollments":
			var input machineEnrollment
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			if input.ID != "" || input.Status != "" {
				t.Errorf("computed fields leaked into create: %#v", input)
			}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(registration)
		case request.Method == http.MethodGet && request.URL.Path == "/v1/machine-enrollments/"+registration.ID:
			_ = json.NewEncoder(writer).Encode(registration)
		case request.Method == http.MethodDelete && request.URL.Path == "/v1/machine-enrollments/"+registration.ID:
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client := &stepAPIClient{
		machineEnrollmentURL:   server.URL,
		machineEnrollmentToken: "local-development-token",
		httpClient:             server.Client(),
		authMode:               authModeToken,
	}
	created, err := client.createMachineEnrollment(context.Background(), machineEnrollment{
		AttestorType: registration.AttestorType, AttestorIdentity: registration.AttestorIdentity,
		AttestorClaims: registration.AttestorClaims, MachineIdentity: registration.MachineIdentity,
		SSHPrincipals: registration.SSHPrincipals,
	})
	if err != nil || created.ID != registration.ID {
		t.Fatalf("create: registration=%#v err=%v", created, err)
	}
	read, found, err := client.getMachineEnrollment(context.Background(), registration.ID)
	if err != nil || !found || read.Status != "pending" {
		t.Fatalf("read: registration=%#v found=%v err=%v", read, found, err)
	}
	if err := client.revokeMachineEnrollment(context.Background(), registration.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestInactiveMachineEnrollmentStatuses(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"expired", "revoked"} {
		if !isInactiveMachineEnrollmentStatus(status) {
			t.Fatalf("expected %q to be inactive", status)
		}
	}
	for _, status := range []string{"pending", "attested", "issued"} {
		if isInactiveMachineEnrollmentStatus(status) {
			t.Fatalf("expected %q to be active", status)
		}
	}
}

func TestMachineEnrollmentJWKAuthTargetsStepCAValidationEndpoint(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &stepAPIClient{
		baseURL:           "https://ca.example",
		authMode:          authModeJWK,
		adminSubject:      "terraform-admin",
		adminSigner:       key,
		adminSignerAlg:    jose.ES256,
		adminX5CCertChain: []string{"Y2VydA=="},
		adminCertExpiry:   time.Now().Add(time.Hour),
	}

	token, err := client.machineEnrollmentAuthHeader(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT format: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
		Issuer   string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Audience != "https://ca.example/admin/admins" {
		t.Fatalf("unexpected audience: %#v", claims.Audience)
	}
	if claims.Subject != "terraform-admin" || claims.Issuer != adminIssuer {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestNormalizeMachineEnrollmentURL(t *testing.T) {
	t.Parallel()
	if got := normalizeMachineEnrollmentURL("", "https://ca.example/"); got != "https://ca.example/machine-enrollment" {
		t.Fatalf("default URL = %q", got)
	}
	if got := normalizeMachineEnrollmentURL(" https://broker.example/api/ ", "https://ca.example"); got != "https://broker.example/api" {
		t.Fatalf("explicit URL = %q", got)
	}
}

func TestMachineEnrollmentTransportSecurity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		url                string
		localToken         string
		insecureSkipVerify bool
		wantError          bool
	}{
		{name: "production HTTPS", url: "https://broker.example", wantError: false},
		{name: "production HTTP", url: "http://broker.example", wantError: true},
		{name: "production insecure TLS", url: "https://broker.example", insecureSkipVerify: true, wantError: true},
		{name: "local development HTTP", url: "http://127.0.0.1:8000", localToken: "local-token", wantError: false},
		{name: "invalid scheme", url: "file:///tmp/socket", localToken: "local-token", wantError: true},
		{name: "relative URL", url: "/machine-enrollment", localToken: "local-token", wantError: true},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := &stepAPIClient{
				machineEnrollmentURL:   test.url,
				machineEnrollmentToken: test.localToken,
				insecureSkipVerify:     test.insecureSkipVerify,
			}
			err := client.validateMachineEnrollmentTransport()
			if (err != nil) != test.wantError {
				t.Fatalf("validateMachineEnrollmentTransport() error = %v, wantError = %v", err, test.wantError)
			}
		})
	}
}
