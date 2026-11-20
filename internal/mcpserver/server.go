// Package mcpserver registers the read-only Keycloak MCP tools and transports.
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
type Service = keycloak.Service

type realmInput struct {
	Realm string `json:"realm,omitempty" jsonschema:"optional target realm; defaults to configured KEYCLOAK_REALM and must be in KEYCLOAK_ALLOWED_REALMS"`
}

type pageInput struct {
	First int  `json:"first,omitempty" jsonschema:"zero-based page offset; must not be negative"`
	Max   *int `json:"max,omitempty" jsonschema:"page size between 1 and 100; defaults to 50"`
}

type countOutput struct {
	Count int `json:"count"`
}

type toolDeps struct {
	service     Service
	timeout     time.Duration
	logger      *slog.Logger
	annotations *mcp.ToolAnnotations
}

// New constructs the MCP server and registers all read-only Keycloak tools.
func New(service Service, timeout time.Duration, logger *slog.Logger) *mcp.Server {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "gocloak-mcp",
		Version: "0.2.0",
	}, &mcp.ServerOptions{Logger: logger})

	deps := toolDeps{
		service:     service,
		timeout:     timeout,
		logger:      logger,
		annotations: readOnlyAnnotations(),
	}
	registerUserTools(server, deps)
	registerClientTools(server, deps)
	registerRoleTools(server, deps)
	registerGroupTools(server, deps)
	registerRealmTools(server, deps)
	registerAuthIDPOrgTools(server, deps)
	return server
}

func readOnlyAnnotations() *mcp.ToolAnnotations {
	destructive := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		IdempotentHint:  true,
		DestructiveHint: &destructive,
	}
}

func executeTool[T any](
	ctx context.Context,
	deps toolDeps,
	toolName string,
	fn func(context.Context) (T, error),
) (*mcp.CallToolResult, T, error) {
	var zero T
	requestCtx, cancel := context.WithTimeout(ctx, deps.timeout)
	defer cancel()
	result, err := fn(requestCtx)
	if err != nil {
		logToolFailure(deps.logger, toolName)
		return nil, zero, errors.New("keycloak request failed")
	}
	return nil, result, nil
}

func logToolFailure(logger *slog.Logger, tool string) {
	if logger != nil {
		logger.Warn("keycloak tool request failed", "tool", tool)
	}
}

func sanitizeErr(err error) error {
	if err != nil {
		return errors.New("keycloak request failed")
	}
	return nil
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
