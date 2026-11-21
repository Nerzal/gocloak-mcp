package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listAuthzResourcesInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	Name       string `json:"name,omitempty" jsonschema:"optional resource name filter"`
	Owner      string `json:"owner,omitempty" jsonschema:"optional resource owner filter"`
	Type       string `json:"type,omitempty" jsonschema:"optional resource type filter"`
	URI        string `json:"uri,omitempty" jsonschema:"optional resource URI filter"`
	Scope      string `json:"scope,omitempty" jsonschema:"optional resource scope filter"`
}

type authzResourceIDInput struct {
	realmInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	ResourceID string `json:"resourceId" jsonschema:"authorization resource UUID"`
}

type listAuthzScopesInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	Name       string `json:"name,omitempty" jsonschema:"optional scope name filter"`
}

type authzScopeIDInput struct {
	realmInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	ScopeID    string `json:"scopeId" jsonschema:"authorization scope UUID"`
}

type listAuthzPoliciesInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	Name       string `json:"name,omitempty" jsonschema:"optional policy name filter"`
	Type       string `json:"type,omitempty" jsonschema:"optional policy type filter"`
}

type authzPolicyIDInput struct {
	realmInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	PolicyID   string `json:"policyId" jsonschema:"authorization policy UUID"`
}

type listAuthzPermissionsInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	Name       string `json:"name,omitempty" jsonschema:"optional permission name filter"`
	Resource   string `json:"resource,omitempty" jsonschema:"optional resource filter"`
	Scope      string `json:"scope,omitempty" jsonschema:"optional scope filter"`
	Type       string `json:"type,omitempty" jsonschema:"optional permission type filter"`
}

type authzPermissionIDInput struct {
	realmInput
	ClientUUID   string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	PermissionID string `json:"permissionId" jsonschema:"authorization permission UUID"`
}

type authzResourcesOutput struct {
	Resources []keycloak.AuthzResourceInfo `json:"resources"`
}

type authzScopesOutput struct {
	Scopes []keycloak.AuthzScopeInfo `json:"scopes"`
}

type authzPoliciesOutput struct {
	Policies []keycloak.AuthzPolicyInfo `json:"policies"`
}

type authzPermissionsOutput struct {
	Permissions []keycloak.AuthzPermissionInfo `json:"permissions"`
}

type namedRefsOutput struct {
	Items []keycloak.NamedRef `json:"items"`
}

func registerAuthzTools(server *mcp.Server, deps toolDeps) {
	registerAuthzResourceTools(server, deps)
	registerAuthzScopeTools(server, deps)
	registerAuthzPolicyCoreTools(server, deps)
	registerAuthzPolicyRelationTools(server, deps)
	registerAuthzPermissionTools(server, deps)
}

func registerAuthzResourceTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_resource_server",
		Description: "Get fine-grained authorization server settings for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientUUIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_resource_server", func(rCtx context.Context) (keycloak.ResourceServerInfo, error) {
			res, callErr := deps.service.GetResourceServer(rCtx, in.Realm, in.ClientUUID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "list_authz_resources",
		Description: "List fine-grained authorization resources for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listAuthzResourcesInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		filter := keycloak.AuthzResourceFilter{Name: in.Name, Owner: in.Owner, Type: in.Type, URI: in.URI, Scope: in.Scope}
		return executeTool(ctx, deps, "list_authz_resources", func(rCtx context.Context) (authzResourcesOutput, error) {
			resources, callErr := deps.service.ListAuthzResources(rCtx, in.Realm, in.ClientUUID, first, maxSize, &filter)
			return authzResourcesOutput{Resources: resources}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_authz_resource",
		Description: "Get a single fine-grained authorization resource by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authzResourceIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_authz_resource", func(rCtx context.Context) (keycloak.AuthzResourceInfo, error) {
			res, callErr := deps.service.GetAuthzResource(rCtx, in.Realm, in.ClientUUID, in.ResourceID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerAuthzScopeTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_authz_scopes",
		Description: "List fine-grained authorization scopes for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listAuthzScopesInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_authz_scopes", func(rCtx context.Context) (authzScopesOutput, error) {
			scopes, callErr := deps.service.ListAuthzScopes(rCtx, in.Realm, in.ClientUUID, first, maxSize, in.Name)
			return authzScopesOutput{Scopes: scopes}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_authz_scope",
		Description: "Get a single fine-grained authorization scope by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authzScopeIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_authz_scope", func(rCtx context.Context) (keycloak.AuthzScopeInfo, error) {
			res, callErr := deps.service.GetAuthzScope(rCtx, in.Realm, in.ClientUUID, in.ScopeID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerAuthzPolicyCoreTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_authz_policies",
		Description: "List fine-grained authorization policies for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listAuthzPoliciesInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		filter := keycloak.AuthzPolicyFilter{Name: in.Name, Type: in.Type}
		return executeTool(ctx, deps, "list_authz_policies", func(rCtx context.Context) (authzPoliciesOutput, error) {
			policies, callErr := deps.service.ListAuthzPolicies(rCtx, in.Realm, in.ClientUUID, first, maxSize, filter)
			return authzPoliciesOutput{Policies: policies}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_authz_policy",
		Description: "Get a single fine-grained authorization policy by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authzPolicyIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_authz_policy", func(rCtx context.Context) (keycloak.AuthzPolicyInfo, error) {
			res, callErr := deps.service.GetAuthzPolicy(rCtx, in.Realm, in.ClientUUID, in.PolicyID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerAuthzPolicyRelationTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_policy_associated_policies",
		Description: "List policies associated with an authorization policy or permission.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authzPolicyIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_policy_associated_policies", func(rCtx context.Context) (authzPoliciesOutput, error) {
			policies, callErr := deps.service.GetPolicyAssociatedPolicies(rCtx, in.Realm, in.ClientUUID, in.PolicyID)
			return authzPoliciesOutput{Policies: policies}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_policy_resources",
		Description: "List resources associated with an authorization policy or permission.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authzPolicyIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_policy_resources", func(rCtx context.Context) (namedRefsOutput, error) {
			items, callErr := deps.service.GetPolicyResources(rCtx, in.Realm, in.ClientUUID, in.PolicyID)
			return namedRefsOutput{Items: items}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_policy_scopes",
		Description: "List scopes associated with an authorization policy or permission.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authzPolicyIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_policy_scopes", func(rCtx context.Context) (namedRefsOutput, error) {
			items, callErr := deps.service.GetPolicyScopes(rCtx, in.Realm, in.ClientUUID, in.PolicyID)
			return namedRefsOutput{Items: items}, sanitizeErr(callErr)
		})
	})
}

func registerAuthzPermissionTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_authz_permissions",
		Description: "List fine-grained authorization permissions for a Keycloak client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listAuthzPermissionsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		filter := keycloak.AuthzPermissionFilter{Name: in.Name, Resource: in.Resource, Scope: in.Scope, Type: in.Type}
		return executeTool(ctx, deps, "list_authz_permissions", func(rCtx context.Context) (authzPermissionsOutput, error) {
			perms, callErr := deps.service.ListAuthzPermissions(rCtx, in.Realm, in.ClientUUID, first, maxSize, filter)
			return authzPermissionsOutput{Permissions: perms}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_authz_permission",
		Description: "Get a single fine-grained authorization permission by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in authzPermissionIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_authz_permission", func(rCtx context.Context) (keycloak.AuthzPermissionInfo, error) {
			res, callErr := deps.service.GetAuthzPermission(rCtx, in.Realm, in.ClientUUID, in.PermissionID)
			return res, sanitizeErr(callErr)
		})
	})
}
