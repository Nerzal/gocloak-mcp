package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type flowIDInput struct {
	realmInput
	FlowID string `json:"flowId" jsonschema:"authentication flow UUID"`
}

type flowAliasInput struct {
	realmInput
	FlowAlias string `json:"flowAlias" jsonschema:"authentication flow alias (e.g. browser)"`
}

type authenticatorConfigIDInput struct {
	realmInput
	ConfigID string `json:"configId" jsonschema:"authenticator configuration UUID"`
}

type requiredActionAliasInput struct {
	realmInput
	Alias string `json:"alias" jsonschema:"required action alias (e.g. CONFIGURE_TOTP)"`
}

type idpAliasInput struct {
	realmInput
	Alias string `json:"alias" jsonschema:"identity provider alias"`
}

type idpMapperIDInput struct {
	realmInput
	Alias    string `json:"alias" jsonschema:"identity provider alias"`
	MapperID string `json:"mapperId" jsonschema:"identity provider mapper UUID"`
}

type authFlowsOutput struct {
	Flows []keycloak.AuthFlowInfo `json:"flows"`
}

type flowExecutionsOutput struct {
	Executions []keycloak.FlowExecutionInfo `json:"executions"`
}

type requiredActionsOutput struct {
	RequiredActions []keycloak.RequiredActionInfo `json:"requiredActions"`
}

type unregisteredRequiredActionsOutput struct {
	RequiredActions []keycloak.UnregisteredRequiredActionInfo `json:"requiredActions"`
}

type identityProvidersOutput struct {
	IdentityProviders []keycloak.IdentityProviderInfo `json:"identityProviders"`
}

type identityProviderMappersOutput struct {
	Mappers []keycloak.IdentityProviderMapperInfo `json:"mappers"`
}

func registerAuthIDPOrgTools(server *mcp.Server, deps toolDeps) {
	registerAuthFlowTools(server, deps)
	registerRequiredActionTools(server, deps)
	registerIdentityProviderTools(server, deps)
}

func registerAuthFlowTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_authentication_flows",
		Description: "List authentication flows configured in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_authentication_flows", func(rCtx context.Context) (authFlowsOutput, error) {
			flows, callErr := deps.service.ListAuthenticationFlows(rCtx, in.Realm)
			return authFlowsOutput{Flows: flows}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_authentication_flow",
		Description: "Get a single authentication flow by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in flowIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_authentication_flow", func(rCtx context.Context) (keycloak.AuthFlowInfo, error) {
			res, callErr := deps.service.GetAuthenticationFlow(rCtx, in.Realm, in.FlowID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_flow_executions",
		Description: "List executions within a Keycloak authentication flow.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in flowAliasInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_flow_executions", func(rCtx context.Context) (flowExecutionsOutput, error) {
			execs, callErr := deps.service.GetFlowExecutions(rCtx, in.Realm, in.FlowAlias)
			return flowExecutionsOutput{Executions: execs}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_authenticator_config",
		Description: "Get safe authenticator execution configuration by config UUID (redacting secret keys).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authenticatorConfigIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_authenticator_config", func(rCtx context.Context) (keycloak.AuthenticatorConfigInfo, error) {
			res, callErr := deps.service.GetAuthenticatorConfig(rCtx, in.Realm, in.ConfigID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerRequiredActionTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_required_actions",
		Description: "List required actions configured in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_required_actions", func(rCtx context.Context) (requiredActionsOutput, error) {
			actions, callErr := deps.service.ListRequiredActions(rCtx, in.Realm)
			return requiredActionsOutput{RequiredActions: actions}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_required_action",
		Description: "Get a single required action by alias.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in requiredActionAliasInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_required_action", func(rCtx context.Context) (keycloak.RequiredActionInfo, error) {
			res, callErr := deps.service.GetRequiredAction(rCtx, in.Realm, in.Alias)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "list_unregistered_required_actions",
		Description: "List available unregistered required actions in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_unregistered_required_actions", func(rCtx context.Context) (unregisteredRequiredActionsOutput, error) {
			actions, callErr := deps.service.ListUnregisteredRequiredActions(rCtx, in.Realm)
			return unregisteredRequiredActionsOutput{RequiredActions: actions}, sanitizeErr(callErr)
		})
	})
}

func registerIdentityProviderTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_identity_providers",
		Description: "List identity providers in a Keycloak realm (without secret config).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_identity_providers", func(rCtx context.Context) (identityProvidersOutput, error) {
			idps, callErr := deps.service.ListIdentityProviders(rCtx, in.Realm)
			return identityProvidersOutput{IdentityProviders: idps}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_identity_provider",
		Description: "Get safe metadata for a single identity provider by alias.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in idpAliasInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_identity_provider", func(rCtx context.Context) (keycloak.IdentityProviderInfo, error) {
			res, callErr := deps.service.GetIdentityProvider(rCtx, in.Realm, in.Alias)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "list_identity_provider_mappers",
		Description: "List mappers configured for a Keycloak identity provider (without secret config).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in idpAliasInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_identity_provider_mappers", func(rCtx context.Context) (identityProviderMappersOutput, error) {
			mappers, callErr := deps.service.ListIdentityProviderMappers(rCtx, in.Realm, in.Alias)
			return identityProviderMappersOutput{Mappers: mappers}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_identity_provider_mapper",
		Description: "Get a single identity provider mapper by alias and mapper UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in idpMapperIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_identity_provider_mapper", func(rCtx context.Context) (keycloak.IdentityProviderMapperInfo, error) {
			res, callErr := deps.service.GetIdentityProviderMapper(rCtx, in.Realm, in.Alias, in.MapperID)
			return res, sanitizeErr(callErr)
		})
	})
}
