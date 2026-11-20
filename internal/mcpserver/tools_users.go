package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listUsersInput struct {
	realmInput
	pageInput
	Search   string `json:"search,omitempty" jsonschema:"optional search query matching username, email, first or last name"`
	Username string `json:"username,omitempty" jsonschema:"optional username filter"`
	Email    string `json:"email,omitempty" jsonschema:"optional email filter"`
	Exact    bool   `json:"exact,omitempty" jsonschema:"require exact match for username/email filters"`
}

type countUsersInput struct {
	realmInput
	Search   string `json:"search,omitempty" jsonschema:"optional search query"`
	Username string `json:"username,omitempty" jsonschema:"optional username filter"`
	Email    string `json:"email,omitempty" jsonschema:"optional email filter"`
	Exact    bool   `json:"exact,omitempty" jsonschema:"require exact match"`
}

type userIDInput struct {
	realmInput
	UserID string `json:"userId" jsonschema:"Keycloak user UUID"`
}

type userGroupsInput struct {
	realmInput
	pageInput
	UserID string `json:"userId" jsonschema:"Keycloak user UUID"`
}

type usersOutput struct {
	Users []keycloak.User `json:"users"`
}

type userSessionsOutput struct {
	Sessions []keycloak.UserSession `json:"sessions"`
}

func registerUserTools(server *mcp.Server, deps toolDeps) {
	registerListAndGetUsers(server, deps)
	registerUserRelations(server, deps)
}

func registerListAndGetUsers(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_users",
		Description: "List or search users in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listUsersInput) (*mcp.CallToolResult, usersOutput, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, usersOutput{}, err
		}
		filter := keycloak.UserFilter{Search: in.Search, Username: in.Username, Email: in.Email, Exact: in.Exact}
		return executeTool(ctx, deps, "list_users", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.ListUsers(rCtx, in.Realm, first, maxSize, filter)
			return usersOutput{Users: users}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_user",
		Description: "Get a single user by UUID in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, keycloak.User, error) {
		return executeTool(ctx, deps, "get_user", func(rCtx context.Context) (keycloak.User, error) {
			return deps.service.GetUser(rCtx, in.Realm, in.UserID)
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "count_users",
		Description: "Count users in a Keycloak realm with optional search filters.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in countUsersInput) (*mcp.CallToolResult, countOutput, error) {
		filter := keycloak.UserFilter{Search: in.Search, Username: in.Username, Email: in.Email, Exact: in.Exact}
		return executeTool(ctx, deps, "count_users", func(rCtx context.Context) (countOutput, error) {
			count, callErr := deps.service.CountUsers(rCtx, in.Realm, filter)
			return countOutput{Count: count}, callErr
		})
	})
}

func registerUserRelations(server *mcp.Server, deps toolDeps) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_user_sessions",
		Description: "List active sessions for a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, userSessionsOutput, error) {
		return executeTool(ctx, deps, "get_user_sessions", func(rCtx context.Context) (userSessionsOutput, error) {
			sessions, callErr := deps.service.GetUserSessions(rCtx, in.Realm, in.UserID)
			return userSessionsOutput{Sessions: sessions}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_user_groups",
		Description: "List groups a Keycloak user belongs to.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userGroupsInput) (*mcp.CallToolResult, groupsOutput, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, groupsOutput{}, err
		}
		return executeTool(ctx, deps, "get_user_groups", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.GetUserGroups(rCtx, in.Realm, in.UserID, first, maxSize)
			return groupsOutput{Groups: groups}, callErr
		})
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_user_roles",
		Description: "List realm and client role mappings assigned to a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, keycloak.RoleMappings, error) {
		return executeTool(ctx, deps, "get_user_roles", func(rCtx context.Context) (keycloak.RoleMappings, error) {
			return deps.service.GetUserRoles(rCtx, in.Realm, in.UserID)
		})
	})
}
