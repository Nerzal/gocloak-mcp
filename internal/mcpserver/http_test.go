package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHTTPServerHealthzAndSecurityHeaders(t *testing.T) {
	srv := NewHTTPServer(New(&stubService{}, 0, nil), "127.0.0.1:8080", "", nil)
	if srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
		t.Fatalf("HTTP server missing hardened timeouts/limits: %+v", srv)
	}

	req := httptest.NewRequest(http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /healthz = %d, headers=%v", rec.Code, rec.Header())
	}

	postReq := httptest.NewRequest(http.MethodPost, "/healthz", http.NoBody)
	postRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz = %d, want 405", postRec.Code)
	}
}

func TestNewHTTPServerBearerAuth(t *testing.T) {
	token := strings.Repeat("s", 32)
	srv := NewHTTPServer(New(&stubService{}, 0, nil), "127.0.0.1:8080", token, nil)

	unauthReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	unauthRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized || unauthRec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("unauthenticated /mcp = %d, headers=%v", unauthRec.Code, unauthRec.Header())
	}

	wrongReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	wrongReq.Header.Set("Authorization", "Bearer wrong-token")
	wrongRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer /mcp = %d, want 401", wrongRec.Code)
	}

	okReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	okReq.Header.Set("Authorization", "Bearer "+token)
	okRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(okRec, okReq)
	if okRec.Code == http.StatusUnauthorized {
		t.Fatalf("valid bearer /mcp returned 401")
	}
}
