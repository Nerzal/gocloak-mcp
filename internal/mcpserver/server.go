// Package mcpserver registers the read-only Keycloak MCP tools and transports.
package mcpserver

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"log/slog"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
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
) (*mcp.CallToolResult, any, error) {
	started := time.Now()
	requestCtx, cancel := context.WithTimeout(ctx, deps.timeout)
	defer cancel()
	result, err := fn(requestCtx)
	durationMS := time.Since(started).Milliseconds()
	if err != nil {
		auditToolCall(deps.logger, toolName, "error", durationMS)
		return nil, nil, errors.New("keycloak request failed")
	}
	encoded, err := jsonv2.Marshal(result)
	if err != nil {
		auditToolCall(deps.logger, toolName, "error", durationMS)
		return nil, nil, errors.New("keycloak response encoding failed")
	}
	auditToolCall(deps.logger, toolName, "ok", durationMS)
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(encoded)}},
	}, nil, nil
}

func addFastTool[In any](
	server *mcp.Server,
	tool *mcp.Tool,
	handler func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error),
) {
	if tool.InputSchema == nil {
		schema, err := jsonschema.For[In](nil)
		if err != nil {
			panic("invalid input schema for tool " + tool.Name + ": " + err.Error())
		}
		tool.InputSchema = schema
	}
	server.AddTool(tool, wrapFastHandler(handler))
}

func wrapFastHandler[In any](
	handler func(context.Context, *mcp.CallToolRequest, In) (*mcp.CallToolResult, any, error),
) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		in, err := decodeToolArgs[In](req)
		if err != nil {
			return errorToolResult(err), nil
		}
		res, _, err := handler(ctx, req, in)
		if err != nil {
			return errorToolResult(err), nil
		}
		return res, nil
	}
}

func decodeToolArgs[In any](req *mcp.CallToolRequest) (In, error) {
	var in In
	if req == nil || len(req.Params.Arguments) == 0 {
		return in, nil
	}
	if err := jsonv2.Unmarshal(req.Params.Arguments, &in, jsonv2.RejectUnknownMembers(true)); err != nil {
		return in, errors.New("invalid tool arguments")
	}
	return in, nil
}

func errorToolResult(err error) *mcp.CallToolResult {
	var res mcp.CallToolResult
	res.SetError(err)
	return &res
}

func auditToolCall(logger *slog.Logger, tool, outcome string, durationMS int64) {
	if logger == nil {
		return
	}
	if outcome != "ok" {
		logger.Warn("mcp tool invoked", "tool", tool, "outcome", outcome, "duration_ms", durationMS)
		return
	}
	logger.Info("mcp tool invoked", "tool", tool, "outcome", outcome, "duration_ms", durationMS)
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
