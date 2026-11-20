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

type groupMembersInput struct {
	realmInput
	pageInput
	GroupID string `json:"groupId" jsonschema:"Keycloak group UUID"`
}

type groupsOutput struct {
	Groups []keycloak.GroupInfo `json:"groups"`
}

func registerGroupTools(server *mcp.Server, deps toolDeps) {
	registerGroupCoreTools(server, deps)
	registerGroupRelationTools(server, deps)
}

func registerGroupCoreTools(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_groups",
		Description: "List or search groups in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listGroupsInput) (*mcp.CallToolResult, groupsOutput, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, groupsOutput{}, err
		}
		return executeTool(ctx, deps, "list_groups", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.ListGroups(rCtx, in.Realm, first, maxSize, in.Search)
			return groupsOutput{Groups: groups}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "count_groups",
		Description: "Count groups in a Keycloak realm with optional search filter.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in countGroupsInput) (*mcp.CallToolResult, countOutput, error) {
		return executeTool(ctx, deps, "count_groups", func(rCtx context.Context) (countOutput, error) {
			count, callErr := deps.service.CountGroups(rCtx, in.Realm, in.Search)
			return countOutput{Count: count}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_group",
		Description: "Get a single group by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupIDInput) (*mcp.CallToolResult, keycloak.GroupInfo, error) {
		return executeTool(ctx, deps, "get_group", func(rCtx context.Context) (keycloak.GroupInfo, error) {
			return deps.service.GetGroup(rCtx, in.Realm, in.GroupID)
		})
	})
}

func registerGroupRelationTools(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_group_members",
		Description: "List users belonging to a Keycloak group.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupMembersInput) (*mcp.CallToolResult, usersOutput, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, usersOutput{}, err
		}
		return executeTool(ctx, deps, "get_group_members", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.GetGroupMembers(rCtx, in.Realm, in.GroupID, first, maxSize)
			return usersOutput{Users: users}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_group_roles",
		Description: "List realm and client role mappings assigned to a Keycloak group.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in groupIDInput) (*mcp.CallToolResult, keycloak.RoleMappings, error) {
		return executeTool(ctx, deps, "get_group_roles", func(rCtx context.Context) (keycloak.RoleMappings, error) {
			return deps.service.GetGroupRoles(rCtx, in.Realm, in.GroupID)
		})
	})
}
