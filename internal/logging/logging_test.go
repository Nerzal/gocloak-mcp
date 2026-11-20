package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactAttribute(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		key    string
		want   string
	}{
		{name: "access token", key: "access_token", want: "[REDACTED]"},
		{name: "client secret", key: "client-secret", want: "[REDACTED]"},
		{name: "password", key: "password", want: "[REDACTED]"},
		{name: "authorization header", key: "Authorization", want: "[REDACTED]"},
		{name: "bearer", key: "bearer_value", want: "[REDACTED]"},
		{name: "cookie", key: "set-cookie", want: "[REDACTED]"},
		{name: "email", key: "email", want: "[REDACTED]"},
		{name: "sensitive group redacts child", groups: []string{"user"}, key: "id", want: "[REDACTED]"},
		{name: "non-sensitive group keeps child", groups: []string{"request"}, key: "status", want: "ok"},
		{name: "builtin msg passthrough", key: slog.MessageKey, want: "ok"},
		{name: "safe attribute", key: "status", want: "ok"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redactAttribute(tc.groups, slog.String(tc.key, "ok"))
			if got.Value.String() != tc.want {
				t.Fatalf("redactAttribute() = %q, want %q", got.Value.String(), tc.want)
			}
		})
	}
}

func TestLoggerRedactsJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := newLogger(&buf)
	logger.Info("tool call",
		"tool", "list_users",
		"access_token", "secret-jwt",
		slog.Group("user", slog.String("id", "alice-123")),
	)
	out := buf.String()
	if strings.Contains(out, "secret-jwt") || strings.Contains(out, "alice-123") {
		t.Fatalf("logger leaked sensitive values: %s", out)
	}
	if !strings.Contains(out, `"tool":"list_users"`) {
		t.Fatalf("logger dropped safe attribute: %s", out)
	}
}

func TestRedactAttributeRedactsJWTAndBearerValues(t *testing.T) {
	for _, val := range []string{
		"Bearer secret-token-value",
		"eyJhbGciOiJSUzI1NiJ9.payload.sig",
	} {
		got := redactAttribute(nil, slog.String("detail", val))
		if got.Value.String() != "[REDACTED]" {
			t.Fatalf("redactAttribute(detail=%q) = %q, want [REDACTED]", val, got.Value.String())
		}
	}
}

func TestNewReturnsLogger(t *testing.T) {
	if New() == nil {
		t.Fatal("New() = nil")
	}
}
