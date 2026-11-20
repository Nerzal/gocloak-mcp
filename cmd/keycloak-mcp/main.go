package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nerzal/gocloak-mcp/internal/config"
	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
	"github.com/Nerzal/gocloak-mcp/internal/mcpserver"
	"github.com/Nerzal/gocloak/v14"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration")
		os.Exit(1)
	}

	client := gocloak.NewClient(cfg.KeycloakURL)
	client.RestyClient().SetTimeout(cfg.RequestTimeout).SetTransport(&http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
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
		logger.Error("MCP server stopped")
		os.Exit(1)
	}
}
