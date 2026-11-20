package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func BenchmarkInMemoryMCPCallListUsers(b *testing.B) {
	ctx := context.Background()
	server := New(&stubService{}, 0, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = serverSession.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "bench-client", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = session.Close() }()

	params := &mcp.CallToolParams{Name: "list_users"}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := session.CallTool(ctx, params); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPMiddlewareChain(b *testing.B) {
	ctx := context.Background()
	token := strings.Repeat("t", 32)
	handler := withSecurityHeaders(withOriginCheck(withBearerAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), token), toOriginSet([]string{"https://trusted.example"})))

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://trusted.example")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}
