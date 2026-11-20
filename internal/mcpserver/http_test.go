package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewHTTPServerHealthzAndSecurityHeaders(t *testing.T) {
	ctx := context.Background()
	srv := NewHTTPServer(New(&stubService{}, 0, nil), "127.0.0.1:8080", "", nil, nil)
	if srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 || srv.MaxHeaderBytes <= 0 {
		t.Fatalf("HTTP server missing hardened timeouts/limits: %+v", srv)
	}

	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/healthz", http.NoBody)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("GET /healthz = %d, headers=%v", rec.Code, rec.Header())
	}

	postReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "/healthz", http.NoBody)
	postRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /healthz = %d, want 405", postRec.Code)
	}
}

func TestNewHTTPServerBearerAuth(t *testing.T) {
	ctx := context.Background()
	token := strings.Repeat("s", 32)
	srv := NewHTTPServer(New(&stubService{}, 0, nil), "127.0.0.1:8080", token, nil, nil)

	unauthReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(`{}`))
	unauthRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized || unauthRec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("unauthenticated /mcp = %d, headers=%v", unauthRec.Code, unauthRec.Header())
	}

	wrongReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(`{}`))
	wrongReq.Header.Set("Authorization", "Bearer wrong-token")
	wrongRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer /mcp = %d, want 401", wrongRec.Code)
	}

	okReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(`{}`))
	okReq.Header.Set("Authorization", "Bearer "+token)
	okRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(okRec, okReq)
	if okRec.Code == http.StatusUnauthorized {
		t.Fatalf("valid bearer /mcp returned 401")
	}
}

func TestNewHTTPServerOriginValidationPreventsDNSRebinding(t *testing.T) {
	ctx := context.Background()
	srv := NewHTTPServer(New(&stubService{}, 0, nil), "127.0.0.1:8080", "", []string{"https://trusted.example.test"}, nil)

	evilReq := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(`{}`))
	evilReq.Header.Set("Origin", "https://evil.attacker.test")
	evilRec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(evilRec, evilReq)
	if evilRec.Code != http.StatusForbidden {
		t.Fatalf("evil Origin /mcp = %d, want 403", evilRec.Code)
	}

	for _, allowed := range []string{"http://localhost:3000", "http://127.0.0.1:8080", "https://trusted.example.test"} {
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(`{}`))
		req.Header.Set("Origin", allowed)
		rec := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusForbidden {
			t.Errorf("allowed Origin %q was rejected with 403", allowed)
		}
	}
}
