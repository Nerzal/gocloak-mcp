// Package main wires and runs the Keycloak MCP server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nerzal/gocloak/v14"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/config"
	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
	"github.com/Nerzal/gocloak-mcp/internal/logging"
	"github.com/Nerzal/gocloak-mcp/internal/mcpserver"
)

const httpShutdownTimeout = 5 * time.Second

func main() {
	logger := logging.New()
	if err := run(logger); err != nil {
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "reason", err.Error())
		return errors.New("invalid configuration")
	}

	client := newKeycloakClient(&cfg)
	tokenProvider := keycloak.NewTokenProvider(client, cfg.Realm, cfg.ClientID, cfg.ClientSecret, cfg.RequestTimeout)
	service := keycloak.NewService(client, tokenProvider, cfg.Realm, cfg.AllowedRealms)
	server := mcpserver.New(service, cfg.RequestTimeout, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, server, &cfg, logger)
}

func serve(ctx context.Context, server *mcp.Server, cfg *config.Config, logger *slog.Logger) error {
	if cfg.Transport == config.TransportHTTP {
		return serveHTTP(ctx, server, cfg, logger)
	}
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		logger.Error("MCP server stopped")
		return errors.New("MCP server stopped")
	}
	return nil
}

func serveHTTP(ctx context.Context, server *mcp.Server, cfg *config.Config, logger *slog.Logger) error {
	httpSrv := mcpserver.NewHTTPServer(server, cfg.HTTPAddr, cfg.HTTPBearerToken, logger)
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpSrv.ListenAndServe()
	}()
	logger.Info("MCP Streamable HTTP server listening", "addr", cfg.HTTPAddr)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), httpShutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("MCP HTTP server stopped")
			return errors.New("MCP HTTP server stopped")
		}
		return nil
	}
}

func newKeycloakClient(cfg *config.Config) *gocloak.GoCloak {
	client := gocloak.NewClient(cfg.KeycloakURL)
	client.RestyClient().GetClient().CheckRedirect = rejectRedirects
	client.RestyClient().
		SetTimeout(cfg.RequestTimeout).
		SetTransport(newHTTPTransport(cfg.RequestTimeout))
	return client
}

func newHTTPTransport(timeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: true,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}
}

func rejectRedirects(_ *http.Request, _ []*http.Request) error {
	return errors.New("redirects are not permitted")
}
