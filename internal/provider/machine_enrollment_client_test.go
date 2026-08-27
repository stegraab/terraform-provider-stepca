package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
		machineEnrollmentURL: server.URL,
		httpClient:           server.Client(),
		authMode:             authModeToken,
		token:                "local-development-token",
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

func TestNormalizeMachineEnrollmentURL(t *testing.T) {
	t.Parallel()
	if got := normalizeMachineEnrollmentURL("", "https://ca.example/"); got != "https://ca.example/machine-enrollment" {
		t.Fatalf("default URL = %q", got)
	}
	if got := normalizeMachineEnrollmentURL(" https://broker.example/api/ ", "https://ca.example"); got != "https://broker.example/api" {
		t.Fatalf("explicit URL = %q", got)
	}
}
