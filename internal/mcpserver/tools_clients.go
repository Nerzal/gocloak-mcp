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

type clientSessionsInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
}

type listClientRolesInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	Search     string `json:"search,omitempty" jsonschema:"optional role name search"`
}

type clientRoleNameInput struct {
	realmInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	RoleName   string `json:"roleName" jsonschema:"client role name"`
}

type scopeIDInput struct {
	realmInput
	ScopeID string `json:"scopeId" jsonschema:"Keycloak client scope UUID"`
}

type scopeMapperIDInput struct {
	realmInput
	ScopeID  string `json:"scopeId" jsonschema:"Keycloak client scope UUID"`
	MapperID string `json:"mapperId" jsonschema:"Keycloak protocol mapper UUID"`
}

type scopeClientInput struct {
	realmInput
	ScopeID    string `json:"scopeId" jsonschema:"Keycloak client scope UUID"`
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
}

type clientsOutput struct {
	Clients []keycloak.ClientInfo `json:"clients"`
}

type clientScopesOutput struct {
	ClientScopes []keycloak.ClientScopeInfo `json:"clientScopes"`
}

type protocolMappersOutput struct {
	Mappers []keycloak.ProtocolMapperInfo `json:"mappers"`
}

func registerClientTools(server *mcp.Server, deps toolDeps) {
	registerClientCoreTools(server, deps)
	registerClientRoleTools(server, deps)
	registerClientDetailTools(server, deps)
	registerClientSessionTools(server, deps)
	registerClientScopeTools(server, deps)
	registerClientScopeDetailTools(server, deps)
}

func registerClientCoreTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
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

	addFastTool(server, &mcp.Tool{
		Name:        "get_client",
		Description: "Get safe metadata for a single Keycloak client by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client", func(rCtx context.Context) (keycloak.ClientInfo, error) {
			res, callErr := deps.service.GetClient(rCtx, in.Realm, in.ClientUUID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
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

func registerClientRoleTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
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

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_role",
		Description: "Get a single role defined on a Keycloak client by name.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientRoleNameInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_role", func(rCtx context.Context) (keycloak.RoleInfo, error) {
			res, callErr := deps.service.GetClientRole(rCtx, in.Realm, in.ClientUUID, in.RoleName)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerClientDetailTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_client_protocol_mappers",
		Description: "List protocol mappers configured on a Keycloak client (without secret config).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_protocol_mappers", func(rCtx context.Context) (protocolMappersOutput, error) {
			mappers, callErr := deps.service.GetClientProtocolMappers(rCtx, in.Realm, in.ClientUUID)
			return protocolMappersOutput{Mappers: mappers}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_default_scopes",
		Description: "List default client scopes assigned to a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_default_scopes", func(rCtx context.Context) (clientScopesOutput, error) {
			scopes, callErr := deps.service.GetClientDefaultScopes(rCtx, in.Realm, in.ClientUUID)
			return clientScopesOutput{ClientScopes: scopes}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_optional_scopes",
		Description: "List optional client scopes assigned to a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_optional_scopes", func(rCtx context.Context) (clientScopesOutput, error) {
			scopes, callErr := deps.service.GetClientOptionalScopes(rCtx, in.Realm, in.ClientUUID)
			return clientScopesOutput{ClientScopes: scopes}, sanitizeErr(callErr)
		})
	})
}

func registerClientSessionTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_client_scope_mappings",
		Description: "List realm and client role scope mappings configured for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_scope_mappings", func(rCtx context.Context) (keycloak.RoleMappings, error) {
			res, callErr := deps.service.GetClientScopeMappings(rCtx, in.Realm, in.ClientUUID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_sessions",
		Description: "List active user sessions for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientSessionsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "get_client_sessions", func(rCtx context.Context) (userSessionsOutput, error) {
			sessions, callErr := deps.service.GetClientSessions(rCtx, in.Realm, in.ClientUUID, first, maxSize)
			return userSessionsOutput{Sessions: sessions}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_offline_sessions",
		Description: "List offline sessions for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientSessionsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "get_client_offline_sessions", func(rCtx context.Context) (userSessionsOutput, error) {
			sessions, callErr := deps.service.GetClientOfflineSessions(rCtx, in.Realm, in.ClientUUID, first, maxSize)
			return userSessionsOutput{Sessions: sessions}, sanitizeErr(callErr)
		})
	})
}

func registerClientScopeTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_client_scopes",
		Description: "List client scopes configured in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_client_scopes", func(rCtx context.Context) (clientScopesOutput, error) {
			scopes, callErr := deps.service.ListClientScopes(rCtx, in.Realm)
			return clientScopesOutput{ClientScopes: scopes}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_scope",
		Description: "Get a single client scope by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scopeIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_scope", func(rCtx context.Context) (keycloak.ClientScopeInfo, error) {
			res, callErr := deps.service.GetClientScope(rCtx, in.Realm, in.ScopeID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_default_default_client_scopes",
		Description: "List realm-level default client scopes automatically assigned as default to new clients.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_default_default_client_scopes", func(rCtx context.Context) (clientScopesOutput, error) {
			scopes, callErr := deps.service.GetDefaultDefaultClientScopes(rCtx, in.Realm)
			return clientScopesOutput{ClientScopes: scopes}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_default_optional_client_scopes",
		Description: "List realm-level optional client scopes automatically assigned as optional to new clients.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_default_optional_client_scopes", func(rCtx context.Context) (clientScopesOutput, error) {
			scopes, callErr := deps.service.GetDefaultOptionalClientScopes(rCtx, in.Realm)
			return clientScopesOutput{ClientScopes: scopes}, sanitizeErr(callErr)
		})
	})
}

func registerClientScopeDetailTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_client_scope_protocol_mappers",
		Description: "List protocol mappers configured on a Keycloak client scope.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scopeIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_client_scope_protocol_mappers", func(rCtx context.Context) (protocolMappersOutput, error) {
			mappers, callErr := deps.service.ListClientScopeProtocolMappers(rCtx, in.Realm, in.ScopeID)
			return protocolMappersOutput{Mappers: mappers}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_scope_protocol_mapper",
		Description: "Get a single protocol mapper on a Keycloak client scope by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scopeMapperIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_scope_protocol_mapper", func(rCtx context.Context) (keycloak.ProtocolMapperInfo, error) {
			res, callErr := deps.service.GetClientScopeProtocolMapper(rCtx, in.Realm, in.ScopeID, in.MapperID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_scope_realm_roles",
		Description: "List realm roles mapped to a Keycloak client scope.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scopeIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_scope_realm_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetClientScopeRealmRoles(rCtx, in.Realm, in.ScopeID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_client_scope_client_roles",
		Description: "List client roles mapped to a Keycloak client scope for a given client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in scopeClientInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_client_scope_client_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetClientScopeClientRoles(rCtx, in.Realm, in.ScopeID, in.ClientUUID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})
}
