package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type listOrgsInput struct {
	realmInput
	pageInput
	Search string `json:"search,omitempty" jsonschema:"optional organization search query"`
}

type countOrgsInput struct {
	realmInput
	Search string `json:"search,omitempty" jsonschema:"optional organization search query"`
}

type orgIDInput struct {
	realmInput
	OrganizationID string `json:"organizationId" jsonschema:"Keycloak organization UUID"`
}

type orgMembersInput struct {
	realmInput
	pageInput
	OrganizationID string `json:"organizationId" jsonschema:"Keycloak organization UUID"`
	Search         string `json:"search,omitempty" jsonschema:"optional member search query"`
}

type orgMemberIDInput struct {
	realmInput
	OrganizationID string `json:"organizationId" jsonschema:"Keycloak organization UUID"`
	UserID         string `json:"userId" jsonschema:"Keycloak user UUID"`
}

type organizationsOutput struct {
	Organizations []keycloak.OrganizationInfo `json:"organizations"`
}

type orgMembersOutput struct {
	Members []keycloak.OrganizationMember `json:"members"`
}

type orgInvitationsOutput struct {
	Invitations []keycloak.OrganizationInvitationInfo `json:"invitations"`
}

func registerOrganizationTools(server *mcp.Server, deps toolDeps) {
	registerOrgCoreTools(server, deps)
	registerOrgMemberTools(server, deps)
	registerOrgRelationTools(server, deps)
}

func registerOrgCoreTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
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

	addFastTool(server, &mcp.Tool{
		Name:        "get_organization",
		Description: "Get a single Keycloak 26+ organization by UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in orgIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_organization", func(rCtx context.Context) (keycloak.OrganizationInfo, error) {
			res, callErr := deps.service.GetOrganization(rCtx, in.Realm, in.OrganizationID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "count_organizations",
		Description: "Count Keycloak 26+ organizations in a realm with optional search filter.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in countOrgsInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "count_organizations", func(rCtx context.Context) (count64Output, error) {
			count, callErr := deps.service.CountOrganizations(rCtx, in.Realm, in.Search)
			return count64Output{Count: count}, sanitizeErr(callErr)
		})
	})
}

func registerOrgMemberTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
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

	addFastTool(server, &mcp.Tool{
		Name:        "count_organization_members",
		Description: "Count members of a Keycloak 26+ organization.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in orgIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "count_organization_members", func(rCtx context.Context) (countOutput, error) {
			count, callErr := deps.service.CountOrganizationMembers(rCtx, in.Realm, in.OrganizationID)
			return countOutput{Count: count}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_organization_member",
		Description: "Get a single member of a Keycloak 26+ organization by user UUID.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in orgMemberIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_organization_member", func(rCtx context.Context) (keycloak.OrganizationMember, error) {
			res, callErr := deps.service.GetOrganizationMember(rCtx, in.Realm, in.OrganizationID, in.UserID)
			return res, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "get_user_organizations",
		Description: "List Keycloak 26+ organizations a user belongs to.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in userIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "get_user_organizations", func(rCtx context.Context) (organizationsOutput, error) {
			orgs, callErr := deps.service.GetUserOrganizations(rCtx, in.Realm, in.UserID)
			return organizationsOutput{Organizations: orgs}, sanitizeErr(callErr)
		})
	})
}

func registerOrgRelationTools(server *mcp.Server, deps toolDeps) {
	addFastTool(server, &mcp.Tool{
		Name:        "list_organization_identity_providers",
		Description: "List identity providers linked to a Keycloak 26+ organization (without secret config).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in orgIDInput) (*mcp.CallToolResult, any, error) {
		return executeTool(ctx, deps, "list_organization_identity_providers", func(rCtx context.Context) (identityProvidersOutput, error) {
			idps, callErr := deps.service.ListOrganizationIdentityProviders(rCtx, in.Realm, in.OrganizationID)
			return identityProvidersOutput{IdentityProviders: idps}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "list_organization_invitations",
		Description: "List pending invitations for a Keycloak 26+ organization (without invite bearer links).",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in orgMembersInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_organization_invitations", func(rCtx context.Context) (orgInvitationsOutput, error) {
			invitations, callErr := deps.service.ListOrganizationInvitations(rCtx, in.Realm, in.OrganizationID, first, maxSize, in.Search)
			return orgInvitationsOutput{Invitations: invitations}, sanitizeErr(callErr)
		})
	})

	addFastTool(server, &mcp.Tool{
		Name:        "list_organization_groups",
		Description: "List groups belonging to a Keycloak 26+ organization.",
		Annotations: deps.annotations,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in orgMembersInput) (*mcp.CallToolResult, any, error) {
		first, maxSize, err := validatePage(in.pageInput)
		if err != nil {
			return nil, nil, err
		}
		return executeTool(ctx, deps, "list_organization_groups", func(rCtx context.Context) (groupsOutput, error) {
			groups, callErr := deps.service.ListOrganizationGroups(rCtx, in.Realm, in.OrganizationID, first, maxSize, in.Search)
			return groupsOutput{Groups: groups}, sanitizeErr(callErr)
		})
	})
}
