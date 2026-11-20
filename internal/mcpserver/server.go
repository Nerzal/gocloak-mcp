// Package mcpserver registers the read-only Keycloak MCP tools.
package mcpserver

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

// Service is the read-only Keycloak service required by the MCP handlers.
type Service interface {
	ListUsers(context.Context, int, int) ([]keycloak.User, error)
	ListClients(context.Context, int, int) ([]keycloak.ClientInfo, error)
	GetRealmInfo(context.Context) (keycloak.RealmInfo, error)
}

type pageInput struct {
	First int `json:"first,omitempty" jsonschema:"zero-based page offset; must not be negative"`
	Max   int `json:"max,omitempty" jsonschema:"page size between 1 and 100; defaults to 50"`
}

// New constructs the MCP server and registers the three read-only tools.
func New(service Service, timeout time.Duration, logger *slog.Logger) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "gocloak-mcp",
		Version: "0.1.0",
	}, &mcp.ServerOptions{Logger: logger})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_users",
		Description: "List users in the configured Keycloak realm.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input pageInput) (*mcp.CallToolResult, []keycloak.User, error) {
		return listUsers(ctx, service, timeout, input)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_clients",
		Description: "List clients in the configured Keycloak realm.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input pageInput) (*mcp.CallToolResult, []keycloak.ClientInfo, error) {
		return listClients(ctx, service, timeout, input)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_realm_info",
		Description: "Get basic information about the configured Keycloak realm.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, keycloak.RealmInfo, error) {
		return getRealmInfo(ctx, service, timeout)
	})
	return server
}

func listUsers(ctx context.Context, service Service, timeout time.Duration, input pageInput) (*mcp.CallToolResult, []keycloak.User, error) {
	first, pageSize, err := validatePage(input)
	if err != nil {
		return nil, nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	users, err := service.ListUsers(requestCtx, first, pageSize)
	if err != nil {
		return nil, nil, errors.New("keycloak request failed")
	}
	return nil, users, nil
}

func listClients(ctx context.Context, service Service, timeout time.Duration, input pageInput) (*mcp.CallToolResult, []keycloak.ClientInfo, error) {
	first, pageSize, err := validatePage(input)
	if err != nil {
		return nil, nil, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	clients, err := service.ListClients(requestCtx, first, pageSize)
	if err != nil {
		return nil, nil, errors.New("keycloak request failed")
	}
	return nil, clients, nil
}

func getRealmInfo(ctx context.Context, service Service, timeout time.Duration) (*mcp.CallToolResult, keycloak.RealmInfo, error) {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	realm, err := service.GetRealmInfo(requestCtx)
	if err != nil {
		return nil, keycloak.RealmInfo{}, errors.New("keycloak request failed")
	}
	return nil, realm, nil
}

func validatePage(input pageInput) (first, pageSize int, err error) {
	if input.First < 0 {
		return 0, 0, errors.New("first must not be negative")
	}
	if input.Max == 0 {
		input.Max = 50
	}
	if input.Max < 1 || input.Max > 100 {
		return 0, 0, errors.New("page size must be between 1 and 100")
	}
	return input.First, input.Max, nil
}
