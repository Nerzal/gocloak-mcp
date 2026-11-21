package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listGroupsInput struct {
	realmInput
	pageInput
	Search string `json:"search,omitempty" jsonschema:"optional group name search"`
}

type countGroupsInput struct {
	realmInput
	Search string `json:"search,omitempty" jsonschema:"optional group name search"`
}

type groupIDInput struct {
	realmInput
	GroupID string `json:"groupId" jsonschema:"Keycloak group UUID"`
}

type groupPathInput struct {
	realmInput
	GroupPath string `json:"groupPath" jsonschema:"hierarchical group path (e.g. /engineering/backend)"`
}

type childGroupsInput struct {
	realmInput
	pageInput
	GroupID string `json:"groupId" jsonschema:"parent Keycloak group UUID"`
	Search  string `json:"search,omitempty" jsonschema:"optional child group name search"`
}

type groupMembersInput struct {
	realmInput
	pageInput
	GroupID string `json:"groupId" jsonschema:"Keycloak group UUID"`
}

type groupClientInput struct {
	realmInput
	GroupID    string `json:"groupId" jsonschema:"Keycloak group UUID"`
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
}

type groupsOutput struct {
	Groups []keycloak.GroupInfo `json:"groups"`
}

func registerGroupTools(server *mcp.Server, deps toolDeps) {
	registerGroupCoreTools(server, deps)
	registerGroupHierarchyTools(server, deps)
	registerGroupRelationTools(server, deps)
	registerGroupEffectiveRoleTools(server, deps)
}

func registerGroupCoreTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_groups",
		Description: "List or search groups in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listGroupsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_groups", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.ListGroups(rCtx, in.Realm, first, maxSize, in.Search)
			return groupsOutput{Groups: groups}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "count_groups",
		Description: "Count groups in a Keycloak realm with optional search filter.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in countGroupsInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "count_groups", func(rCtx context.Context) (countOutput, error) {
			count, callErr := deps.service.CountGroups(rCtx, in.Realm, in.Search)
			return countOutput{Count: count}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_group",
		Description: "Get a single group by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_group", func(rCtx context.Context) (keycloak.GroupInfo, error) {
			res, callErr := deps.service.GetGroup(rCtx, in.Realm, in.GroupID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerGroupHierarchyTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_group_by_path",
		Description: "Resolve a Keycloak group by its hierarchical path (e.g. /engineering/backend).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupPathInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_group_by_path", func(rCtx context.Context) (keycloak.GroupInfo, error) {
			res, callErr := deps.service.GetGroupByPath(rCtx, in.Realm, in.GroupPath)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "list_child_groups",
		Description: "List direct child subgroups of a parent Keycloak group.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in childGroupsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_child_groups", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.ListChildGroups(rCtx, in.Realm, in.GroupID, first, maxSize, in.Search)
			return groupsOutput{Groups: groups}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_default_groups",
		Description: "List default groups automatically assigned to newly created users in a realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in realmInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_default_groups", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.GetDefaultGroups(rCtx, in.Realm)
			return groupsOutput{Groups: groups}, sanitizeErr(callErr)
		})
	})
}

func registerGroupRelationTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_group_members",
		Description: "List users belonging to a Keycloak group.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupMembersInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "get_group_members", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.GetGroupMembers(rCtx, in.Realm, in.GroupID, first, maxSize)
			return usersOutput{Users: users}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_group_roles",
		Description: "List realm and client role mappings assigned to a Keycloak group.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_group_roles", func(rCtx context.Context) (keycloak.RoleMappings, error) {
			res, callErr := deps.service.GetGroupRoles(rCtx, in.Realm, in.GroupID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerGroupEffectiveRoleTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_group_composite_realm_roles",
		Description: "List effective realm roles for a group including composite roles.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_group_composite_realm_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetGroupCompositeRealmRoles(rCtx, in.Realm, in.GroupID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_group_composite_client_roles",
		Description: "List effective client roles for a group including composite roles.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupClientInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_group_composite_client_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetGroupCompositeClientRoles(rCtx, in.Realm, in.GroupID, in.ClientUUID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_group_available_realm_roles",
		Description: "List realm roles available to assign to a Keycloak group.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_group_available_realm_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetGroupAvailableRealmRoles(rCtx, in.Realm, in.GroupID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_group_available_client_roles",
		Description: "List client roles available to assign to a Keycloak group.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupClientInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_group_available_client_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetGroupAvailableClientRoles(rCtx, in.Realm, in.GroupID, in.ClientUUID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})
}
