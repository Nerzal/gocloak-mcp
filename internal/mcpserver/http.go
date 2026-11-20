package mcpserver

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpIdleTimeout       = 60 * time.Second
	httpMaxHeaderBytes    = 1 << 20
)

// NewHTTPServer builds a hardened Streamable HTTP server exposing /mcp and /healthz.
func NewHTTPServer(server *mcp.Server, addr, bearerToken string, logger *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{Logger: logger})

	mux.Handle("/mcp", withSecurityHeaders(withBearerAuth(mcpHandler, bearerToken)))
	mux.Handle("/healthz", withSecurityHeaders(http.HandlerFunc(handleHealthz)))

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    httpMaxHeaderBytes,
	}
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func withBearerAuth(next http.Handler, expectedToken string) http.Handler {
	if expectedToken == "" {
		return next
	}
	expectedBytes := []byte(expectedToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(token), expectedBytes) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
