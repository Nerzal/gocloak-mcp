package main

import (
	"bytes"
	"crypto/tls"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Nerzal/gocloak-mcp/internal/config"
)

func TestNewHTTPTransportHardening(t *testing.T) {
	timeout := 45 * time.Second
	transport := newHTTPTransport(timeout)
	if transport.Proxy == nil {
		t.Fatal("Proxy = nil, want http.ProxyFromEnvironment")
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 = false, want true")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("TLSClientConfig.MinVersion = %v, want >= TLS 1.2", transport.TLSClientConfig)
	}
	if transport.ResponseHeaderTimeout != timeout {
		t.Fatalf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, timeout)
	}
}

func TestNewKeycloakClientBlocksRedirects(t *testing.T) {
	client := newKeycloakClient(&config.Config{
		KeycloakURL:    "https://keycloak.example.test",
		Realm:          "example",
		ClientID:       "mcp",
		ClientSecret:   "secret",
		RequestTimeout: 30 * time.Second,
	})
	checkRedirect := client.RestyClient().GetClient().CheckRedirect
	if checkRedirect == nil {
		t.Fatal("CheckRedirect = nil, want redirect blocker")
	}
	if err := checkRedirect(&http.Request{}, nil); err == nil {
		t.Fatal("CheckRedirect() = nil, want error blocking redirect")
	}
}

func TestRunFailsFastOnInvalidConfig(t *testing.T) {
	t.Setenv("KEYCLOAK_URL", "http://remote.example.test")
	t.Setenv("KEYCLOAK_REALM", "example")
	t.Setenv("KEYCLOAK_CLIENT_ID", "mcp")
	t.Setenv("KEYCLOAK_CLIENT_SECRET", "secret")

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	if err := run(logger); err == nil {
		t.Fatal("run() = nil, want error")
	}
	out := buf.String()
	if !strings.Contains(out, "invalid configuration") || !strings.Contains(out, "KEYCLOAK_URL") {
		t.Fatalf("unexpected log output: %s", out)
	}
}
