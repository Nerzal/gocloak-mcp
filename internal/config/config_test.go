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
	if cfg.Realm != "example" || cfg.RequestTimeout != defaultRequestTimeout || cfg.Transport != TransportStdio {
		t.Fatalf("Load() = %+v", cfg)
	}
	if len(cfg.AllowedRealms) != 1 || cfg.AllowedRealms[0] != "example" {
		t.Fatalf("AllowedRealms = %v, want [example]", cfg.AllowedRealms)
	}
}

func TestLoadCustomTimeoutAndAllowedRealms(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("KEYCLOAK_REQUEST_TIMEOUT", "30s")
	t.Setenv("KEYCLOAK_ALLOWED_REALMS", "tenant-a, example, tenant-b, tenant-a")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RequestTimeout != 30*time.Second {
		t.Fatalf("RequestTimeout = %v, want 30s", cfg.RequestTimeout)
	}
	if len(cfg.AllowedRealms) != 3 {
		t.Fatalf("AllowedRealms = %v, want 3 unique realms", cfg.AllowedRealms)
	}
}

func TestLoadHTTPTransportLoopbackAndNonLoopback(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("MCP_TRANSPORT", "http")
	t.Setenv("MCP_HTTP_ADDR", "127.0.0.1:9090")
	if cfg, err := Load(); err != nil || cfg.HTTPAddr != "127.0.0.1:9090" {
		t.Fatalf("Load(loopback http) = %+v, %v", cfg, err)
	}

	t.Setenv("MCP_HTTP_ADDR", "0.0.0.0:9090")
	t.Setenv("MCP_HTTP_BEARER_TOKEN", "short")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_HTTP_BEARER_TOKEN") {
		t.Fatalf("Load(non-loopback short token) error = %v", err)
	}

	t.Setenv("MCP_HTTP_BEARER_TOKEN", strings.Repeat("a", 32))
	if _, err := Load(); err != nil {
		t.Fatalf("Load(non-loopback valid token) error = %v", err)
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
		{name: "invalid allowed realm", key: "KEYCLOAK_ALLOWED_REALMS", val: "good,../bad", want: "KEYCLOAK_ALLOWED_REALMS"},
		{name: "whitespace client ID", key: "KEYCLOAK_CLIENT_ID", val: "   ", want: "KEYCLOAK_CLIENT_ID"},
		{name: "empty secret", key: "KEYCLOAK_CLIENT_SECRET", val: "", want: "KEYCLOAK_CLIENT_SECRET"},
		{name: "whitespace secret", key: "KEYCLOAK_CLIENT_SECRET", val: "   ", want: "KEYCLOAK_CLIENT_SECRET"},
		{name: "timeout too large", key: "KEYCLOAK_REQUEST_TIMEOUT", val: "3m", want: "KEYCLOAK_REQUEST_TIMEOUT"},
		{name: "non-positive timeout", key: "KEYCLOAK_REQUEST_TIMEOUT", val: "0s", want: "KEYCLOAK_REQUEST_TIMEOUT"},
		{name: "unparseable timeout", key: "KEYCLOAK_REQUEST_TIMEOUT", val: "not-a-duration", want: "KEYCLOAK_REQUEST_TIMEOUT"},
		{name: "invalid transport", key: "MCP_TRANSPORT", val: "sse", want: "MCP_TRANSPORT"},
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

func TestLoadRejectsInvalidHTTPAddr(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("MCP_TRANSPORT", "http")
	t.Setenv("MCP_HTTP_ADDR", "not-a-host-port")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MCP_HTTP_ADDR") {
		t.Fatalf("Load() error = %v, want MCP_HTTP_ADDR error", err)
	}
}

func TestValidateRejectsURLCredentials(t *testing.T) {
	cfg := Config{
		KeycloakURL:    "https://" + "alice:pw@" + "example.test",
		Realm:          "example",
		ClientID:       "client",
		ClientSecret:   "secret",
		RequestTimeout: defaultRequestTimeout,
		Transport:      TransportStdio,
	}
	if err := cfg.Validate(); err == nil || strings.Contains(err.Error(), "pw") {
		t.Fatalf("Validate() error = %v, want sanitized URL validation error", err)
	}
}

func TestConfigRedactsSecretsInStringAndLogValue(t *testing.T) {
	const secret = "super-sensitive-value"
	const bearer = "super-sensitive-bearer-token-value-12345"
	cfg := Config{
		KeycloakURL:     "https://keycloak.example.test",
		Realm:           "example",
		ClientID:        "mcp",
		ClientSecret:    secret,
		RequestTimeout:  defaultRequestTimeout,
		Transport:       TransportHTTP,
		HTTPAddr:        "127.0.0.1:8080",
		HTTPBearerToken: bearer,
	}
	if formatted := fmt.Sprintf("%+v", cfg); strings.Contains(formatted, secret) || strings.Contains(formatted, bearer) {
		t.Fatalf("String() leaked secret: %q", formatted)
	}
	if logged := cfg.LogValue().String(); strings.Contains(logged, secret) || strings.Contains(logged, bearer) {
		t.Fatalf("LogValue() leaked secret: %q", logged)
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
	t.Setenv("KEYCLOAK_ALLOWED_REALMS", "")
	t.Setenv("KEYCLOAK_CLIENT_ID", "mcp")
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "not-a-real-secret")
	t.Setenv("KEYCLOAK_REQUEST_TIMEOUT", "")
	t.Setenv("MCP_TRANSPORT", "")
	t.Setenv("MCP_HTTP_ADDR", "")
	t.Setenv("MCP_HTTP_BEARER_TOKEN", "")
}
