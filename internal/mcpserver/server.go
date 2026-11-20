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

const (
	defaultRequestTimeout = 15 * time.Second
	defaultPageSize       = 50
	maxPageSize           = 100
)

// Service is the read-only Keycloak service required by the MCP handlers.
type Service interface {
	ListUsers(context.Context, int, int) ([]keycloak.User, error)
	ListClients(context.Context, int, int) ([]keycloak.ClientInfo, error)
	GetRealmInfo(context.Context) (keycloak.RealmInfo, error)
}

type pageInput struct {
	First int  `json:"first,omitempty" jsonschema:"zero-based page offset; must not be negative"`
	Max   *int `json:"max,omitempty" jsonschema:"page size between 1 and 100; defaults to 50"`
}

type usersOutput struct {
	Users []keycloak.User `json:"users"`
}

type clientsOutput struct {
	Clients []keycloak.ClientInfo `json:"clients"`
}

// New constructs the MCP server and registers the three read-only tools.
func New(service Service, timeout time.Duration, logger *slog.Logger) *mcp.Server {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "gocloak-mcp",
		Version: "0.1.0",
	}, &mcp.ServerOptions{Logger: logger})
	registerTools(server, service, timeout, logger)
	return server
}

func registerTools(server *mcp.Server, service Service, timeout time.Duration, logger *slog.Logger) {
	annotations := readOnlyAnnotations()
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_users",
		Description: "List users in the configured Keycloak realm.",
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input pageInput) (*mcp.CallToolResult, usersOutput, error) {
		return listUsers(ctx, service, timeout, logger, input)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_clients",
		Description: "List clients in the configured Keycloak realm.",
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input pageInput) (*mcp.CallToolResult, clientsOutput, error) {
		return listClients(ctx, service, timeout, logger, input)
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_realm_info",
		Description: "Get basic information about the configured Keycloak realm.",
		Annotations: annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, keycloak.RealmInfo, error) {
		return getRealmInfo(ctx, service, timeout, logger)
	})
}

func readOnlyAnnotations() *mcp.ToolAnnotations {
	destructive := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		DestructiveHint: &destructive,
	}
}

func listUsers(ctx context.Context, service Service, timeout time.Duration, logger *slog.Logger, input pageInput) (*mcp.CallToolResult, usersOutput, error) {
	first, pageSize, err := validatePage(input)
	if err != nil {
		return nil, usersOutput{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	users, err := service.ListUsers(requestCtx, first, pageSize)
	if err != nil {
		logToolFailure(logger, "list_users")
		return nil, usersOutput{}, errors.New("keycloak request failed")
	}
	return nil, usersOutput{Users: users}, nil
}

func listClients(ctx context.Context, service Service, timeout time.Duration, logger *slog.Logger, input pageInput) (*mcp.CallToolResult, clientsOutput, error) {
	first, pageSize, err := validatePage(input)
	if err != nil {
		return nil, clientsOutput{}, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	clients, err := service.ListClients(requestCtx, first, pageSize)
	if err != nil {
		logToolFailure(logger, "list_clients")
		return nil, clientsOutput{}, errors.New("keycloak request failed")
	}
	return nil, clientsOutput{Clients: clients}, nil
}

func getRealmInfo(ctx context.Context, service Service, timeout time.Duration, logger *slog.Logger) (*mcp.CallToolResult, keycloak.RealmInfo, error) {
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	realm, err := service.GetRealmInfo(requestCtx)
	if err != nil {
		logToolFailure(logger, "get_realm_info")
		return nil, keycloak.RealmInfo{}, errors.New("keycloak request failed")
	}
	return nil, realm, nil
}

func logToolFailure(logger *slog.Logger, tool string) {
	if logger != nil {
		logger.Warn("keycloak tool request failed", "tool", tool)
	}
}

func validatePage(input pageInput) (first, pageSize int, err error) {
	if input.First < 0 {
		return 0, 0, errors.New("first must not be negative")
	}
	pageSize = defaultPageSize
	if input.Max != nil {
		pageSize = *input.Max
	}
	if pageSize < 1 || pageSize > maxPageSize {
		return 0, 0, errors.New("page size must be between 1 and 100")
	}
	return input.First, pageSize, nil
}
