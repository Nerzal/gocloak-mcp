package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
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

func TestLoadCustomTimeout(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("KEYCLOAK_REQUEST_TIMEOUT", "30s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Fatalf("RequestTimeout = %v, want 30s", cfg.RequestTimeout)
	}
}

type invalidConfigCase struct {
	name string
	key  string
	val  string
	want string
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	cases := []invalidConfigCase{
		{name: "remote HTTP URL", key: "KEYCLOAK_URL", val: "http://keycloak.example.test", want: "KEYCLOAK_URL"},
		{name: "unsupported scheme", key: "KEYCLOAK_URL", val: "ftp://keycloak.example.test", want: "KEYCLOAK_URL"},
		{name: "empty hostname with port", key: "KEYCLOAK_URL", val: "https://:443", want: "KEYCLOAK_URL"},
		{name: "trailing query delimiter", key: "KEYCLOAK_URL", val: "https://keycloak.example.test?", want: "KEYCLOAK_URL"},
		{name: "trailing fragment delimiter", key: "KEYCLOAK_URL", val: "https://keycloak.example.test#", want: "KEYCLOAK_URL"},
		{name: "realm with slash", key: "KEYCLOAK_REALM", val: "../admin", want: "KEYCLOAK_REALM"},
		{name: "dot realm", key: "KEYCLOAK_REALM", val: ".", want: "KEYCLOAK_REALM"},
		{name: "dot-dot realm", key: "KEYCLOAK_REALM", val: "..", want: "KEYCLOAK_REALM"},
		{name: "whitespace client ID", key: "KEYCLOAK_CLIENT_ID", val: "   ", want: "KEYCLOAK_CLIENT_ID"},
		{name: "empty secret", key: "KEYCLOAK_CLIENT_SECRET", val: "", want: "KEYCLOAK_CLIENT_SECRET"},
		{name: "whitespace secret", key: "KEYCLOAK_CLIENT_SECRET", val: "   ", want: "KEYCLOAK_CLIENT_SECRET"},
		{name: "timeout too large", key: "KEYCLOAK_REQUEST_TIMEOUT", val: "3m", want: "KEYCLOAK_REQUEST_TIMEOUT"},
		{name: "non-positive timeout", key: "KEYCLOAK_REQUEST_TIMEOUT", val: "0s", want: "KEYCLOAK_REQUEST_TIMEOUT"},
		{name: "unparseable timeout", key: "KEYCLOAK_REQUEST_TIMEOUT", val: "not-a-duration", want: "KEYCLOAK_REQUEST_TIMEOUT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv(tc.key, tc.val)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateRejectsURLCredentials(t *testing.T) {
	cfg := Config{
		KeycloakURL:    "https://" + "alice:pw@" + "example.test",
		Realm:          "example",
		ClientID:       "client",
		ClientSecret:   "secret",
		RequestTimeout: defaultRequestTimeout,
	}
	if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "pw") {
		t.Fatalf("Validate() error = %v, want sanitized URL validation error", err)
	}
}

func TestConfigRedactsSecretInStringAndLogValue(t *testing.T) {
	const secret = "super-sensitive-value"
	cfg := Config{
		KeycloakURL:    "https://keycloak.example.test",
		Realm:          "example",
		ClientID:       "mcp",
		ClientSecret:   secret,
		RequestTimeout: defaultRequestTimeout,
	}
	if formatted := fmt.Sprintf("%+v", cfg); strings.Contains(formatted, secret) || !strings.Contains(formatted, "[REDACTED]") {
		t.Fatalf("String() leaked secret or missed redaction: %q", formatted)
	}
	if logged := cfg.LogValue().String(); strings.Contains(logged, secret) || !strings.Contains(logged, "[REDACTED]") {
		t.Fatalf("LogValue() leaked secret or missed redaction: %q", logged)
	}
}

func TestLoadAllowsLoopbackHTTP(t *testing.T) {
	for _, rawURL := range []string{
		"http://127.0.0.1:8080/auth",
		"http://localhost:8080",
		"http://[::1]:8080",
	} {
		t.Run(rawURL, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv("KEYCLOAK_URL", rawURL)
			if _, err := Load(); err != nil {
				t.Fatalf("Load() error = %v", err)
			}
		})
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
