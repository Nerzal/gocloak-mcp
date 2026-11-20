package logging

import (
	"log/slog"
	"testing"
)

func TestRedactAttribute(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{key: "access_token", want: "[REDACTED]"},
		{key: "client-secret", want: "[REDACTED]"},
		{key: "password", want: "[REDACTED]"},
		{key: "email", want: "[REDACTED]"},
		{key: "status", want: "ok"},
	}
	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			got := redactAttribute(nil, slog.String(test.key, "ok"))
			if got.Value.String() != test.want {
				t.Fatalf("redactAttribute() = %q, want %q", got.Value.String(), test.want)
			}
		})
	}
}
