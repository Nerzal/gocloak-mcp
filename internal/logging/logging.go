// Package logging provides a stderr-only JSON logger with sensitive-attribute redaction.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New creates a JSON logger that writes only to standard error.
func New() *slog.Logger {
	return newLogger(os.Stderr)
}

func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		ReplaceAttr: redactAttribute,
	}))
}

func redactAttribute(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) == 0 && isBuiltinKey(attr.Key) {
		return attr
	}
	if isSensitiveKey(attr.Key) || hasSensitiveGroup(groups) || isSensitiveValue(attr.Value) {
		return slog.String(attr.Key, "[REDACTED]")
	}
	return attr
}

func isSensitiveValue(val slog.Value) bool {
	if val.Kind() != slog.KindString {
		return false
	}
	s := val.String()
	return strings.HasPrefix(s, "Bearer ") || strings.Contains(s, "eyJhbG")
}

func isBuiltinKey(key string) bool {
	return key == slog.TimeKey || key == slog.LevelKey || key == slog.MessageKey
}

func hasSensitiveGroup(groups []string) bool {
	for _, group := range groups {
		if isSensitiveKey(group) {
			return true
		}
	}
	return false
}

func isSensitiveKey(raw string) bool {
	key := strings.ToLower(raw)
	for _, sensitive := range sensitiveAttributeKeys {
		if strings.Contains(key, sensitive) {
			return true
		}
	}
	return false
}

var sensitiveAttributeKeys = [...]string{
	"token", "secret", "password", "auth", "bearer", "cookie", "session",
	"credential", "jwt", "header", "email", "user", "name", "phone",
	"address", "birth", "error", "err", "response", "body", "stack", "trace",
}
