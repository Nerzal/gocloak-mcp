// Package logging provides a stderr-only JSON logger with sensitive-attribute redaction.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New creates a JSON logger that writes only to standard error.
func New() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		ReplaceAttr: redactAttribute,
	}))
}

func redactAttribute(_ []string, attr slog.Attr) slog.Attr {
	key := strings.ToLower(strings.ReplaceAll(attr.Key, "-", "_"))
	for _, sensitive := range sensitiveAttributeKeys {
		if strings.Contains(key, sensitive) {
			return slog.String(attr.Key, "[REDACTED]")
		}
	}
	return attr
}

var sensitiveAttributeKeys = [...]string{
	"token", "secret", "password", "authorization", "email", "user", "name",
	"phone", "address", "birth", "error", "err", "response", "body", "stack", "trace",
}
