package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestOWASP_MCP01_ToolErrorsNeverLeakTokensOrBodies(t *testing.T) {
	ctx := context.Background()
	const sensitiveMarker = "eyJhbGciOiJSUzI1NiJ9.fixture-payload"
	session, cleanup := connectInMemory(t, &stubService{err: errors.New("HTTP 500 Authorization: Bearer " + sensitiveMarker)}, nil)
	defer cleanup()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_users"})
	if err != nil {
		t.Fatalf("transport error = %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true on upstream failure")
	}
	for _, content := range res.Content {
		if text, ok := content.(*mcp.TextContent); ok && strings.Contains(text.Text, sensitiveMarker) {
			t.Fatalf("tool error leaked fixture marker: %q", text.Text)
		}
	}
}

func TestOWASP_MCP02_MCP03_ToolCatalogIntegrityAndNoPoisoning(t *testing.T) {
	ctx := context.Background()
	session, cleanup := connectInMemory(t, &stubService{}, nil)
	defer cleanup()

	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 32 {
		t.Fatalf("ListTools() = %d, %v; want 32", len(listed.Tools), err)
	}
	poisonMarkers := []string{"ignore previous", "system:", "<script", "disregard"}
	for _, tool := range listed.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint ||
			tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint {
			t.Errorf("tool %q violates read-only policy", tool.Name)
		}
		desc := strings.ToLower(tool.Description)
		for _, marker := range poisonMarkers {
			if strings.Contains(desc, marker) {
				t.Errorf("tool %q description contains suspicious marker %q", tool.Name, marker)
			}
		}
	}
}

func TestOWASP_MCP07_HTTPAuthAndOriginProtection(t *testing.T) {
	ctx := context.Background()
	token := strings.Repeat("k", 32)
	srv := NewHTTPServer(New(&stubService{}, 0, nil), "127.0.0.1:8080", token, nil, nil)

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request = %d, want 403", rec.Code)
	}
}

func TestOWASP_MCP08_StructuredAuditLoggingOnSuccessAndError(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	session, cleanup := connectInMemory(t, &stubService{}, logger)
	defer cleanup()
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_realm_info"}); err != nil {
		t.Fatalf("CallTool error = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"mcp tool invoked"`) ||
		!strings.Contains(out, `"tool":"get_realm_info"`) ||
		!strings.Contains(out, `"outcome":"ok"`) {
		t.Fatalf("missing structured audit log fields: %s", out)
	}
}

func TestOWASP_MCP10_BoundedPaginationPreventsContextOverSharing(t *testing.T) {
	ctx := context.Background()
	session, cleanup := connectInMemory(t, &stubService{}, nil)
	defer cleanup()

	for _, args := range []map[string]any{
		{"max": 0},
		{"max": 101},
		{"first": -1},
	} {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_users", Arguments: args})
		if err != nil {
			t.Fatalf("unexpected transport error for %v: %v", args, err)
		}
		if !res.IsError {
			t.Errorf("expected IsError=true for unbounded pagination args %v", args)
		}
	}
}
