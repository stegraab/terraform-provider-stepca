package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestNormalizeBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		out  string
	}{
		{
			name: "trim spaces and trailing slash",
			in:   "  https://ca.example.com/  ",
			out:  "https://ca.example.com",
		},
		{
			name: "remove admin suffix",
			in:   "https://ca.example.com/admin",
			out:  "https://ca.example.com",
		},
		{
			name: "remove admin suffix with trailing slash",
			in:   "https://ca.example.com/admin/",
			out:  "https://ca.example.com",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeBaseURL(tt.in); got != tt.out {
				t.Fatalf("normalizeBaseURL(%q) = %q, want %q", tt.in, got, tt.out)
			}
		})
	}
}

func TestConfigString(t *testing.T) {
	t.Run("returns explicit config value", func(t *testing.T) {
		got, ok := configString(types.StringValue("from-config"), "STEPCA_TEST_STR", "default")
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != "from-config" {
			t.Fatalf("got %q, want %q", got, "from-config")
		}
	})

	t.Run("falls back to env var", func(t *testing.T) {
		t.Setenv("STEPCA_TEST_STR", "from-env")
		got, ok := configString(types.StringNull(), "STEPCA_TEST_STR", "default")
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != "from-env" {
			t.Fatalf("got %q, want %q", got, "from-env")
		}
	})

	t.Run("falls back to default", func(t *testing.T) {
		envName := "STEPCA_TEST_STR_DEFAULT"
		_ = os.Unsetenv(envName)
		got, ok := configString(types.StringNull(), envName, "default")
		if !ok {
			t.Fatal("expected ok=true")
		}
		if got != "default" {
			t.Fatalf("got %q, want %q", got, "default")
		}
	})
}

func TestConfigBool(t *testing.T) {
	t.Run("returns explicit config value", func(t *testing.T) {
		got, ok := configBool(types.BoolValue(true), "STEPCA_TEST_BOOL", false)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if !got {
			t.Fatal("expected true")
		}
	})

	t.Run("falls back to env var", func(t *testing.T) {
		t.Setenv("STEPCA_TEST_BOOL", "true")
		got, ok := configBool(types.BoolNull(), "STEPCA_TEST_BOOL", false)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if !got {
			t.Fatal("expected true")
		}
	})

	t.Run("invalid env uses default", func(t *testing.T) {
		t.Setenv("STEPCA_TEST_BOOL", "not-a-bool")
		got, ok := configBool(types.BoolNull(), "STEPCA_TEST_BOOL", true)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if !got {
			t.Fatal("expected default true")
		}
	})
}
