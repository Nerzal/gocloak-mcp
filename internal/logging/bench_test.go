package logging

import (
	"log/slog"
	"testing"
)

func BenchmarkRedactAttributeBuiltin(b *testing.B) {
	attr := slog.String(slog.MessageKey, "mcp tool invoked")
	b.ReportAllocs()
	for b.Loop() {
		_ = redactAttribute(nil, attr)
	}
}

func BenchmarkRedactAttributeSafe(b *testing.B) {
	attr := slog.String("tool", "list_users")
	b.ReportAllocs()
	for b.Loop() {
		_ = redactAttribute(nil, attr)
	}
}

func BenchmarkRedactAttributeSensitive(b *testing.B) {
	attr := slog.String("access_token", "eyJhbGciOiJSUzI1NiJ9.payload")
	b.ReportAllocs()
	for b.Loop() {
		_ = redactAttribute(nil, attr)
	}
}
