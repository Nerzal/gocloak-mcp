package config

import (
	"strings"
	"testing"
)

func TestLoadRequiresValidConfiguration(t *testing.T) {
	setRequiredEnvironment(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Realm != "example" || cfg.RequestTimeout != defaultRequestTimeout {
		t.Fatalf("Load() = %+v", cfg)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name string
		set  func(*testing.T)
		want string
	}{
		{
			name: "remote HTTP URL",
			set: func(t *testing.T) {
				t.Setenv("KEYCLOAK_URL", "http://keycloak.example.test")
			},
			want: "KEYCLOAK_URL",
		},
		{
			name: "invalid realm",
			set: func(t *testing.T) {
				t.Setenv("KEYCLOAK_REALM", "../admin")
			},
			want: "KEYCLOAK_REALM",
		},
		{
			name: "empty secret",
			set: func(t *testing.T) {
				t.Setenv("KEYCLOAK_CLIENT_SECRET", "")
			},
			want: "KEYCLOAK_CLIENT_SECRET",
		},
		{
			name: "invalid timeout",
			set: func(t *testing.T) {
				t.Setenv("KEYCLOAK_REQUEST_TIMEOUT", "3m")
			},
			want: "KEYCLOAK_REQUEST_TIMEOUT",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setRequiredEnvironment(t)
			test.set(t)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsURLCredentials(t *testing.T) {
	cfg := Config{
		KeycloakURL:  "https://" + "alice:pw@" + "example.test",
		Realm:        "example",
		ClientID:     "client",
		ClientSecret: "secret",
	}
	if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "pw") {
		t.Fatalf("Validate() error = %v, want sanitized URL validation error", err)
	}
}

func TestLoadAllowsLoopbackHTTP(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("KEYCLOAK_URL", "http://127.0.0.1:8080/auth")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("KEYCLOAK_URL", "https://keycloak.example.test")
	t.Setenv("KEYCLOAK_REALM", "example")
	t.Setenv("KEYCLOAK_CLIENT_ID", "mcp")
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "not-a-real-secret")
	t.Setenv("KEYCLOAK_REQUEST_TIMEOUT", "")
}
