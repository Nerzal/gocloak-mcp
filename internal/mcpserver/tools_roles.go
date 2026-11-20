package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listRolesInput struct {
	realmInput
	pageInput
	Search string `json:"search,omitempty" jsonschema:"optional role name search"`
}

type roleNameInput struct {
	realmInput
	RoleName string `json:"roleName" jsonschema:"realm role name"`
}

type usersInRoleInput struct {
	realmInput
	pageInput
	RoleName string `json:"roleName" jsonschema:"realm role name"`
}

type usersInClientRoleInput struct {
	realmInput
	pageInput
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
	RoleName   string `json:"roleName" jsonschema:"client role name"`
}

type rolesOutput struct {
	Roles []keycloak.RoleInfo `json:"roles"`
}

func registerRoleTools(server *mcp.Server, deps toolDeps) {
	registerRealmRoleQueries(server, deps)
	registerRoleMemberQueries(server, deps)
}

func registerRealmRoleQueries(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_realm_roles",
		Description: "List realm-level roles in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listRolesInput) (*mcp.CallToolResult, rolesOutput, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, rolesOutput{}, err
		}
		return executeTool(ctx, deps, "list_realm_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.ListRealmRoles(rCtx, in.Realm, first, maxSize, in.Search)
			return rolesOutput{Roles: roles}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_realm_role",
		Description: "Get a single realm role by name.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in roleNameInput) (*mcp.CallToolResult, keycloak.RoleInfo, error) {
		return executeTool(ctx, deps, "get_realm_role", func(rCtx context.Context) (keycloak.RoleInfo, error) {
			return deps.service.GetRealmRole(rCtx, in.Realm, in.RoleName)
		})
	})
}

func registerRoleMemberQueries(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_users_in_role",
		Description: "List users assigned to a realm role.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in usersInRoleInput) (*mcp.CallToolResult, usersOutput, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, usersOutput{}, err
		}
		return executeTool(ctx, deps, "get_users_in_role", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.GetUsersInRole(rCtx, in.Realm, in.RoleName, first, maxSize)
			return usersOutput{Users: users}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_users_in_client_role",
		Description: "List users assigned to a specific client role.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in usersInClientRoleInput) (*mcp.CallToolResult, usersOutput, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, usersOutput{}, err
		}
		return executeTool(ctx, deps, "get_users_in_client_role", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.GetUsersInClientRole(rCtx, in.Realm, in.ClientUUID, in.RoleName, first, maxSize)
			return usersOutput{Users: users}, callErr
		})
	})
}
