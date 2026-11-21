package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type flowAliasInput struct {
	realmInput
	FlowAlias string `json:"flowAlias" jsonschema:"authentication flow alias (e.g. browser)"`
}

type idpAliasInput struct {
	realmInput
	Alias string `json:"alias" jsonschema:"identity provider alias"`
}

type listOrgsInput struct {
	realmInput
	pageInput
	Search string `json:"search,omitempty" jsonschema:"optional organization search query"`
}

type orgMembersInput struct {
	realmInput
	pageInput
	OrganizationID string `json:"organizationId" jsonschema:"Keycloak organization UUID"`
	Search         string `json:"search,omitempty" jsonschema:"optional member search query"`
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

type identityProvidersOutput struct {
	IdentityProviders []keycloak.IdentityProviderInfo `json:"identityProviders"`
}

type organizationsOutput struct {
	Organizations []keycloak.OrganizationInfo `json:"organizations"`
}

type orgMembersOutput struct {
	Members []keycloak.OrganizationMember `json:"members"`
}

func registerAuthIDPOrgTools(server *mcp.Server, deps toolDeps) {
	registerAuthFlowTools(server, deps)
	registerIdentityProviderTools(server, deps)
	registerOrganizationTools(server, deps)
}

func registerAuthFlowTools(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_authentication_flows",
		Description: "List authentication flows configured in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_authentication_flows", func(rCtx context.Context) (authFlowsOutput, error) {
			flows, callErr := deps.service.ListAuthenticationFlows(rCtx, in.Realm)
			return authFlowsOutput{Flows: flows}, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_flow_executions",
		Description: "List executions within a Keycloak authentication flow.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in flowAliasInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_flow_executions", func(rCtx context.Context) (flowExecutionsOutput, error) {
			execs, callErr := deps.service.GetFlowExecutions(rCtx, in.Realm, in.FlowAlias)
			return flowExecutionsOutput{Executions: execs}, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_required_actions",
		Description: "List required actions configured in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_required_actions", func(rCtx context.Context) (requiredActionsOutput, error) {
			actions, callErr := deps.service.ListRequiredActions(rCtx, in.Realm)
			return requiredActionsOutput{RequiredActions: actions}, sanitizeErr(callErr)
		})
	})
}

func registerIdentityProviderTools(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_identity_providers",
		Description: "List identity providers in a Keycloak realm (without secret config).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_identity_providers", func(rCtx context.Context) (identityProvidersOutput, error) {
			idps, callErr := deps.service.ListIdentityProviders(rCtx, in.Realm)
			return identityProvidersOutput{IdentityProviders: idps}, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_identity_provider",
		Description: "Get safe metadata for a single identity provider by alias.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in idpAliasInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_identity_provider", func(rCtx context.Context) (keycloak.IdentityProviderInfo, error) {
			res, callErr := deps.service.GetIdentityProvider(rCtx, in.Realm, in.Alias)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerOrganizationTools(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_organizations",
		Description: "List Keycloak 26+ organizations in a realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listOrgsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_organizations", func(rCtx context.Context) (organizationsOutput, error) {
			orgs, callErr := deps.service.ListOrganizations(rCtx, in.Realm, first, maxSize, in.Search)
			return organizationsOutput{Organizations: orgs}, sanitizeErr(callErr)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_organization_members",
		Description: "List members of a Keycloak 26+ organization.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in orgMembersInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "get_organization_members", func(rCtx context.Context) (orgMembersOutput, error) {
			members, callErr := deps.service.GetOrganizationMembers(rCtx, in.Realm, in.OrganizationID, first, maxSize, in.Search)
			return orgMembersOutput{Members: members}, sanitizeErr(callErr)
		})
	})
}
