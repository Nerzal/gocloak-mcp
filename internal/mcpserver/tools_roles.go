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

type roleIDInput struct {
	realmInput
	RoleID string `json:"roleId" jsonschema:"Keycloak role UUID"`
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
	registerRoleCompositeQueries(server, deps)
	registerRoleUserQueries(server, deps)
	registerRoleGroupQueries(server, deps)
}

func registerRealmRoleQueries(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_realm_roles",
		Description: "List realm-level roles in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listRolesInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_realm_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.ListRealmRoles(rCtx, in.Realm, first, maxSize, in.Search)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_realm_role",
		Description: "Get a single realm role by name.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in roleNameInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_realm_role", func(rCtx context.Context) (keycloak.RoleInfo, error) {
			res, callErr := deps.service.GetRealmRole(rCtx, in.Realm, in.RoleName)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_role_by_id",
		Description: "Get a single realm or client role by its UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in roleIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_role_by_id", func(rCtx context.Context) (keycloak.RoleInfo, error) {
			res, callErr := deps.service.GetRoleByID(rCtx, in.Realm, in.RoleID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerRoleCompositeQueries(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_realm_role_composites",
		Description: "List child roles included in a composite realm role by role name.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in roleNameInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_realm_role_composites", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetRealmRoleComposites(rCtx, in.Realm, in.RoleName)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_role_composites_by_id",
		Description: "List child roles included in any composite realm or client role by role UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in roleIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_role_composites_by_id", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetRoleCompositesByID(rCtx, in.Realm, in.RoleID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})
}

func registerRoleUserQueries(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_users_in_role",
		Description: "List users assigned to a realm role.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in usersInRoleInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "get_users_in_role", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.GetUsersInRole(rCtx, in.Realm, in.RoleName, first, maxSize)
			return usersOutput{Users: users}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_users_in_client_role",
		Description: "List users assigned to a specific client role.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in usersInClientRoleInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "get_users_in_client_role", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.GetUsersInClientRole(rCtx, in.Realm, in.ClientUUID, in.RoleName, first, maxSize)
			return usersOutput{Users: users}, sanitizeErr(callErr)
		})
	})
}

func registerRoleGroupQueries(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_groups_in_role",
		Description: "List groups assigned to a realm role.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in roleNameInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_groups_in_role", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.GetGroupsInRole(rCtx, in.Realm, in.RoleName)
			return groupsOutput{Groups: groups}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_groups_in_client_role",
		Description: "List groups assigned to a specific client role.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in clientRoleNameInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_groups_in_client_role", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.GetGroupsInClientRole(rCtx, in.Realm, in.ClientUUID, in.RoleName)
			return groupsOutput{Groups: groups}, sanitizeErr(callErr)
		})
	})
}
