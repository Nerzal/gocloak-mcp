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

type userClientInput struct {
	realmInput
	UserID     string `json:"userId" jsonschema:"Keycloak user UUID"`
	ClientUUID string `json:"clientUuid" jsonschema:"internal Keycloak client UUID"`
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

type userCredentialsOutput struct {
	Credentials []keycloak.UserCredentialInfo `json:"credentials"`
}

type federatedIdentitiesOutput struct {
	Identities []keycloak.FederatedIdentityInfo `json:"identities"`
}

func registerUserTools(server *mcp.Server, deps toolDeps) {
	registerListAndGetUsers(server, deps)
	registerUserRelations(server, deps)
	registerUserSecurityTools(server, deps)
	registerUserEffectiveRoleTools(server, deps)
}

func registerListAndGetUsers(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_users",
		Description: "List or search users in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in listUsersInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		filter := keycloak.UserFilter{Search: in.Search, Username: in.Username, Email: in.Email, Exact: in.Exact}
		return executeTool(ctx, deps, "list_users", func(rCtx context.Context) (usersOutput, error) {
			users, callErr := deps.service.ListUsers(rCtx, in.Realm, first, maxSize, filter)
			return usersOutput{Users: users}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user",
		Description: "Get a single user by UUID in a Keycloak realm.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user", func(rCtx context.Context) (keycloak.User, error) {
			res, callErr := deps.service.GetUser(rCtx, in.Realm, in.UserID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "count_users",
		Description: "Count users in a Keycloak realm with optional search filters.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in countUsersInput) (*mcp.CallToolResult, any, error) {
		filter := keycloak.UserFilter{Search: in.Search, Username: in.Username, Email: in.Email, Exact: in.Exact}
		return executeTool(ctx, deps, "count_users", func(rCtx context.Context) (countOutput, error) {
			count, callErr := deps.service.CountUsers(rCtx, in.Realm, filter)
			return countOutput{Count: count}, sanitizeErr(callErr)
		})
	})
}

func registerUserRelations(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_user_sessions",
		Description: "List active sessions for a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_sessions", func(rCtx context.Context) (userSessionsOutput, error) {
			sessions, callErr := deps.service.GetUserSessions(rCtx, in.Realm, in.UserID)
			return userSessionsOutput{Sessions: sessions}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_offline_sessions",
		Description: "List offline sessions for a Keycloak user on a specific client.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userClientInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_offline_sessions", func(rCtx context.Context) (userSessionsOutput, error) {
			sessions, callErr := deps.service.GetUserOfflineSessions(rCtx, in.Realm, in.UserID, in.ClientUUID)
			return userSessionsOutput{Sessions: sessions}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_groups",
		Description: "List groups a Keycloak user belongs to.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userGroupsInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "get_user_groups", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.GetUserGroups(rCtx, in.Realm, in.UserID, first, maxSize)
			return groupsOutput{Groups: groups}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_roles",
		Description: "List realm and client role mappings assigned to a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_roles", func(rCtx context.Context) (keycloak.RoleMappings, error) {
			res, callErr := deps.service.GetUserRoles(rCtx, in.Realm, in.UserID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerUserSecurityTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_user_credentials",
		Description: "List safe credential metadata (type, label, createdDate) for a user without exposing secret hashes or values.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_credentials", func(rCtx context.Context) (userCredentialsOutput, error) {
			creds, callErr := deps.service.GetUserCredentials(rCtx, in.Realm, in.UserID)
			return userCredentialsOutput{Credentials: creds}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_federated_identities",
		Description: "List external identity provider links associated with a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_federated_identities", func(rCtx context.Context) (federatedIdentitiesOutput, error) {
			ids, callErr := deps.service.GetUserFederatedIdentities(rCtx, in.Realm, in.UserID)
			return federatedIdentitiesOutput{Identities: ids}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_brute_force_status",
		Description: "Get brute-force attack detection and lockout status for a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_brute_force_status", func(rCtx context.Context) (keycloak.BruteForceStatusInfo, error) {
			res, callErr := deps.service.GetUserBruteForceStatus(rCtx, in.Realm, in.UserID)
			return res, sanitizeErr(callErr)
		})
	})
}

func registerUserEffectiveRoleTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "get_user_composite_realm_roles",
		Description: "List effective realm roles for a user including roles inherited through composites and groups.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_composite_realm_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetUserCompositeRealmRoles(rCtx, in.Realm, in.UserID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_composite_client_roles",
		Description: "List effective client roles for a user including roles inherited through composites and groups.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userClientInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_composite_client_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetUserCompositeClientRoles(rCtx, in.Realm, in.UserID, in.ClientUUID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_available_realm_roles",
		Description: "List realm roles available to assign to a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_available_realm_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetUserAvailableRealmRoles(rCtx, in.Realm, in.UserID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_available_client_roles",
		Description: "List client roles available to assign to a Keycloak user.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userClientInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_available_client_roles", func(rCtx context.Context) (rolesOutput, error) {
			roles, callErr := deps.service.GetUserAvailableClientRoles(rCtx, in.Realm, in.UserID, in.ClientUUID)
			return rolesOutput{Roles: roles}, sanitizeErr(callErr)
		})
	})
}
