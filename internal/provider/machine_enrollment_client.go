package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type machineEnrollment struct {
	ID               string            `json:"id,omitempty"`
	AttestorType     string            `json:"attestor_type"`
	AttestorIdentity string            `json:"attestor_identity"`
	AttestorClaims   map[string]string `json:"attestor_claims"`
	MachineIdentity  string            `json:"machine_identity"`
	SSHPrincipals    []string          `json:"ssh_principals"`
	Status           string            `json:"status,omitempty"`
}

func (c *stepAPIClient) createMachineEnrollment(ctx context.Context, input machineEnrollment) (machineEnrollment, error) {
	return c.requestMachineEnrollment(ctx, http.MethodPost, "/v1/machine-enrollments", input)
}

func (c *stepAPIClient) getMachineEnrollment(ctx context.Context, id string) (machineEnrollment, bool, error) {
	registration, err := c.requestMachineEnrollment(ctx, http.MethodGet, "/v1/machine-enrollments/"+url.PathEscape(id), nil)
	var statusErr *apiStatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
		return machineEnrollment{}, false, nil
	}
	return registration, err == nil, err
}

func (c *stepAPIClient) revokeMachineEnrollment(ctx context.Context, id string) error {
	_, err := c.requestMachineEnrollment(ctx, http.MethodDelete, "/v1/machine-enrollments/"+url.PathEscape(id), nil)
	var statusErr *apiStatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}

func (c *stepAPIClient) requestMachineEnrollment(ctx context.Context, method string, path string, payload any) (machineEnrollment, error) {
	if err := c.validateMachineEnrollmentTransport(); err != nil {
		return machineEnrollment{}, err
	}
	fullURL := c.machineEnrollmentURL + path
	authHeader, err := c.machineEnrollmentAuthHeader(ctx)
	if err != nil {
		return machineEnrollment{}, err
	}
	body, err := c.requestWithAuth(ctx, method, fullURL, payload, authHeader)
	if err != nil {
		return machineEnrollment{}, err
	}
	if len(body) == 0 {
		return machineEnrollment{}, nil
	}
	var registration machineEnrollment
	if err := json.Unmarshal(body, &registration); err != nil {
		return machineEnrollment{}, err
	}
	return registration, nil
}

func (c *stepAPIClient) validateMachineEnrollmentTransport() error {
	endpoint, err := url.Parse(c.machineEnrollmentURL)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "https" && endpoint.Scheme != "http") {
		return errors.New("machine enrollment URL must be an absolute HTTP(S) URL")
	}

	if strings.TrimSpace(c.machineEnrollmentToken) != "" {
		return nil
	}
	if endpoint.Scheme != "https" {
		return errors.New("JWK-authenticated machine enrollment requires HTTPS")
	}
	if c.insecureSkipVerify {
		return errors.New("JWK-authenticated machine enrollment requires TLS certificate verification")
	}
	return nil
}

func (c *stepAPIClient) machineEnrollmentAuthHeader(ctx context.Context) (string, error) {
	if token := strings.TrimSpace(c.machineEnrollmentToken); token != "" {
		return token, nil
	}
	if c.authMode != authModeJWK {
		return "", errors.New("machine enrollment requires JWK administrator authentication or machine_enrollment_token for local development")
	}
	if err := c.ensureAdminIdentity(ctx); err != nil {
		return "", err
	}
	return c.generateAdminJWT(c.baseURL + "/admin/admins")
}
