package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listClientsInput struct {
	realmInput
	pageInput
	ClientID string `json:"clientId,omitempty" jsonschema:"optional clientId filter"`
}

type clientUUIDInput struct {
	realmInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
}

type listClientRolesInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	Search     string `json:"search,omitempty" jsonschema:"optional role name search"`
}

type scopeIDInput struct {
	realmInput
	ScopeID string `json:"scopeId" jsonschema:"Keycloak client scope UUID"`
}

type clientsOutput struct {
	Clients []keycloak.ClientInfo `json:"clients"`
}

type clientScopesOutput struct {
	ClientScopes []keycloak.ClientScopeInfo `json:"clientScopes"`
}

func registerClientTools(server *mcp.Server, deps toolDeps) {
	registerClientCoreTools(server, deps)
	registerClientRoleAndScopeTools(server, deps)
}

func registerClientCoreTools(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_clients",
		Description: "List clients in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listClientsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_clients", func(rCtx context.Context) (clientsOutput, error) {
			clients, callErr := deps.service.ListClients(rCtx, in.Realm, first, maxSize, keycloak.ClientFilter{ClientID: in.ClientID})
			return clientsOutput{Clients: clients}, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_client",
		Description: "Get safe metadata for a single Keycloak client by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client", func(rCtx context.Context) (keycloak.ClientInfo, error) {
			res, callErr := deps.service.GetClient(rCtx, in.Realm, in.ClientUUID)
			return res, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_client_service_account",
		Description: "Get the service-account user associated with a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_service_account", func(rCtx context.Context) (keycloak.User, error) {
			res, callErr := deps.service.GetClientServiceAccount(rCtx, in.Realm, in.ClientUUID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerClientRoleAndScopeTools(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_client_roles",
		Description: "List roles defined on a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listClientRolesInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_client_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.ListClientRoles(rCtx, in.Realm, in.ClientUUID, first, maxSize, in.Search)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_client_scopes",
		Description: "List client scopes configured in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_client_scopes", func(rCtx context.Context) (clientScopesOutput, error) {
			scopes, callErr := deps.service.ListClientScopes(rCtx, in.Realm)
			return clientScopesOutput{ClientScopes: scopes}, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_client_scope",
		Description: "Get a single client scope by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scopeIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_scope", func(rCtx context.Context) (keycloak.ClientScopeInfo, error) {
			res, callErr := deps.service.GetClientScope(rCtx, in.Realm, in.ScopeID)
			return res, sanitizeErr(callErr)
		})
	})
}
