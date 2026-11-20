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

func main() {
	logger := logging.New()
	if err := run(logger); err != nil {
		logger.Error("MCP server stopped")
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return errors.New("invalid configuration")
	}

	client := gocloak.NewClient(cfg.KeycloakURL)
	client.RestyClient().SetTimeout(cfg.RequestTimeout).SetTransport(&http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	})
	tokenProvider := keycloak.NewTokenProvider(client, cfg.Realm, cfg.ClientID, cfg.ClientSecret)
	service := keycloak.NewService(client, tokenProvider, cfg.Realm)
	server := mcpserver.New(service, cfg.RequestTimeout, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return errors.New("MCP server stopped")
	}
	return nil
}
