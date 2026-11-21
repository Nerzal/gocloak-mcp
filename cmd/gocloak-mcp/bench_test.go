package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Nerzal/gocloak-mcp/internal/config"
	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
	"github.com/Nerzal/gocloak-mcp/internal/mcpserver"
)

func newMockKeycloakServer(b *testing.B, userCount int) *httptest.Server {
	b.Helper()
	users := make([]map[string]any, userCount)
	for i := range users {
		users[i] = map[string]any{
			"id":               fmt.Sprintf("00000000-0000-4000-8000-%012d", i),
			"username":         fmt.Sprintf("user-%03d", i),
			"email":            fmt.Sprintf("user-%03d@example.test", i),
			"firstName":        fmt.Sprintf("First%d", i),
			"lastName":         fmt.Sprintf("Last%d", i),
			"enabled":          true,
			"emailVerified":    true,
			"createdTimestamp": 1700000000000 + i*1000,
		}
	}
	usersBody, err := json.Marshal(users)
	if err != nil {
		b.Fatal(err)
	}
	tokenBody := []byte(`{"access_token":"header.payload.sig","expires_in":3600,"token_type":"Bearer"}`)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_, _ = w.Write(tokenBody)
			return
		}
		_, _ = w.Write(usersBody)
	}))
}

func initMCPSession(b *testing.B, client *http.Client, url string) string {
	b.Helper()
	initBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"bench","version":"1.0"}}}`)
	req, err := http.NewRequestWithContext(b.Context(), http.MethodPost, url, bytes.NewReader(initBody))
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("initialize status = %d", resp.StatusCode)
	}
	sessionID := resp.Header.Get("Mcp-Session-Id")

	notifBody := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	nReq, err := http.NewRequestWithContext(b.Context(), http.MethodPost, url, bytes.NewReader(notifBody))
	if err != nil {
		b.Fatal(err)
	}
	nReq.Header.Set("Content-Type", "application/json")
	nReq.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		nReq.Header.Set("Mcp-Session-Id", sessionID)
	}
	nResp, err := client.Do(nReq)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, nResp.Body)
	_ = nResp.Body.Close()
	return sessionID
}

func postMCPBench(b *testing.B, client *http.Client, url, sessionID string, body []byte) {
	b.Helper()
	req, err := http.NewRequestWithContext(b.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		b.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := client.Do(req)
	if err != nil {
		b.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b.Fatalf("call status = %d", resp.StatusCode)
	}
}

func BenchmarkEndToEndHTTPListUsers50(b *testing.B) {
	kcSrv := newMockKeycloakServer(b, 50)
	defer kcSrv.Close()

	cfg := config.Config{
		KeycloakURL:    kcSrv.URL,
		Realm:          "example",
		AllowedRealms:  []string{"example"},
		ClientID:       "gocloak-mcp",
		ClientSecret:   "bench-secret",
		RequestTimeout: 15 * time.Second,
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	kcClient := newKeycloakClient(&cfg)
	tokenProvider := keycloak.NewTokenProvider(kcClient, cfg.Realm, cfg.ClientID, cfg.ClientSecret, cfg.RequestTimeout)
	service := keycloak.NewService(kcClient, tokenProvider, cfg.Realm, cfg.AllowedRealms)
	mcpSrv := mcpserver.New(service, cfg.RequestTimeout, logger)

	httpSrv := mcpserver.NewHTTPServer(mcpSrv, "127.0.0.1:0", "", nil, logger)
	ts := httptest.NewServer(httpSrv.Handler)
	defer ts.Close()

	client := ts.Client()
	mcpURL := ts.URL + "/mcp"
	sessionID := initMCPSession(b, client, mcpURL)
	callBody := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_users","arguments":{"max":50}}}`)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		postMCPBench(b, client, mcpURL, sessionID, callBody)
	}
}
