// Package keycloak provides read-only Keycloak services backed by GoCloak.
package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v15"
)

var _ Client = (*gocloak.GoCloak)(nil)

// Client is the read-only subset of GoCloak used by the MCP server.
type Client interface {
	GetToken(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error)

	// Users & Attack Detection
	GetUsers(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error)
	GetUserByID(context.Context, string, string, string) (*gocloak.User, error)
	GetUserCount(context.Context, string, string, gocloak.GetUsersParams) (int, error)
	GetUserSessions(context.Context, string, string, string) ([]*gocloak.UserSessionRepresentation, error)
	GetUserOfflineSessionsForClient(context.Context, string, string, string, string) ([]*gocloak.UserSessionRepresentation, error)
	GetUserGroups(context.Context, string, string, string, gocloak.GetGroupsParams) ([]*gocloak.Group, error)
	GetRoleMappingByUserID(context.Context, string, string, string) (*gocloak.MappingsRepresentation, error)
	GetCredentials(context.Context, string, string, string) ([]*gocloak.CredentialRepresentation, error)
	GetUserFederatedIdentities(context.Context, string, string, string) ([]*gocloak.FederatedIdentityRepresentation, error)
	GetUserBruteForceDetectionStatus(context.Context, string, string, string) (*gocloak.BruteForceStatus, error)
	GetCompositeRealmRolesByUserID(context.Context, string, string, string) ([]*gocloak.Role, error)
	GetCompositeClientRolesByUserID(context.Context, string, string, string, string) ([]*gocloak.Role, error)
	GetAvailableRealmRolesByUserID(context.Context, string, string, string) ([]*gocloak.Role, error)
	GetAvailableClientRolesByUserID(context.Context, string, string, string, string) ([]*gocloak.Role, error)

	// Clients & Client Scopes
	GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error)
	GetClient(context.Context, string, string, string) (*gocloak.Client, error)
	GetClientServiceAccount(context.Context, string, string, string) (*gocloak.User, error)
	GetClientRoles(context.Context, string, string, string, gocloak.GetRoleParams) ([]*gocloak.Role, error)
	GetClientRole(context.Context, string, string, string, string) (*gocloak.Role, error)
	GetClientsDefaultScopes(context.Context, string, string, string) ([]*gocloak.ClientScope, error)
	GetClientsOptionalScopes(context.Context, string, string, string) ([]*gocloak.ClientScope, error)
	GetClientScopeMappings(context.Context, string, string, string) (*gocloak.MappingsRepresentation, error)
	GetClientUserSessions(context.Context, string, string, string, ...gocloak.GetClientUserSessionsParams) ([]*gocloak.UserSessionRepresentation, error)
	GetClientOfflineSessions(context.Context, string, string, string, ...gocloak.GetClientUserSessionsParams) ([]*gocloak.UserSessionRepresentation, error)
	GetClientScopes(context.Context, string, string) ([]*gocloak.ClientScope, error)
	GetClientScope(context.Context, string, string, string) (*gocloak.ClientScope, error)
	GetClientScopeProtocolMappers(context.Context, string, string, string) ([]*gocloak.ProtocolMappers, error)
	GetClientScopeProtocolMapper(context.Context, string, string, string, string) (*gocloak.ProtocolMappers, error)
	GetDefaultDefaultClientScopes(context.Context, string, string) ([]*gocloak.ClientScope, error)
	GetDefaultOptionalClientScopes(context.Context, string, string) ([]*gocloak.ClientScope, error)
	GetClientScopesScopeMappingsRealmRoles(context.Context, string, string, string) ([]*gocloak.Role, error)
	GetClientScopesScopeMappingsClientRoles(context.Context, string, string, string, string) ([]*gocloak.Role, error)

	// Roles
	GetRealmRoles(context.Context, string, string, gocloak.GetRoleParams) ([]*gocloak.Role, error)
	GetRealmRole(context.Context, string, string, string) (*gocloak.Role, error)
	GetRealmRoleByID(context.Context, string, string, string) (*gocloak.Role, error)
	GetCompositeRealmRoles(context.Context, string, string, string) ([]*gocloak.Role, error)
	GetCompositeRolesByRoleID(context.Context, string, string, string) ([]*gocloak.Role, error)
	GetUsersByRoleName(context.Context, string, string, string, gocloak.GetUsersByRoleParams) ([]*gocloak.User, error)
	GetUsersByClientRoleName(context.Context, string, string, string, string, gocloak.GetUsersByRoleParams) ([]*gocloak.User, error)
	GetGroupsByRole(context.Context, string, string, string) ([]*gocloak.Group, error)
	GetGroupsByClientRole(context.Context, string, string, string, string) ([]*gocloak.Group, error)

	// Groups
	GetGroups(context.Context, string, string, gocloak.GetGroupsParams) ([]*gocloak.Group, error)
	GetGroupsCount(context.Context, string, string, gocloak.GetGroupsParams) (int, error)
	GetGroup(context.Context, string, string, string) (*gocloak.Group, error)
	GetGroupByPath(context.Context, string, string, string) (*gocloak.Group, error)
	GetChildGroups(context.Context, string, string, string, gocloak.GetChildGroupsParams) ([]*gocloak.Group, error)
	GetDefaultGroups(context.Context, string, string) ([]*gocloak.Group, error)
	GetGroupMembers(context.Context, string, string, string, gocloak.GetGroupsParams) ([]*gocloak.User, error)
	GetRoleMappingByGroupID(context.Context, string, string, string) (*gocloak.MappingsRepresentation, error)
	GetCompositeRealmRolesByGroupID(context.Context, string, string, string) ([]*gocloak.Role, error)
	GetCompositeClientRolesByGroupID(context.Context, string, string, string, string) ([]*gocloak.Role, error)
	GetAvailableRealmRolesByGroupID(context.Context, string, string, string) ([]*gocloak.Role, error)
	GetAvailableClientRolesByGroupID(context.Context, string, string, string, string) ([]*gocloak.Role, error)

	// Realms, Keys, Events & Server Info
	GetRealms(context.Context, string) ([]*gocloak.RealmRepresentation, error)
	GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error)
	GetEvents(context.Context, string, string, gocloak.GetEventsParams) ([]*gocloak.EventRepresentation, error)
	GetAdminEvents(context.Context, string, string, gocloak.GetAdminEventsParams) ([]*gocloak.AdminEventRepresentation, error)
	GetKeyStoreConfig(context.Context, string, string) (*gocloak.KeyStoreConfig, error)
	GetCerts(context.Context, string) (*gocloak.CertResponse, error)
	GetIssuer(context.Context, string) (*gocloak.IssuerResponse, error)
	GetUserProfileConfig(context.Context, string, string) (*gocloak.UserProfileConfig, error)
	GetServerInfo(context.Context, string) (*gocloak.ServerInfoRepresentation, error)

	// Authentication Flows, Required Actions & Identity Providers
	GetAuthenticationFlows(context.Context, string, string) ([]*gocloak.AuthenticationFlowRepresentation, error)
	GetAuthenticationFlow(context.Context, string, string, string) (*gocloak.AuthenticationFlowRepresentation, error)
	GetAuthenticationExecutions(context.Context, string, string, string) ([]*gocloak.ModifyAuthenticationExecutionRepresentation, error)
	GetAuthenticatorConfig(context.Context, string, string, string) (*gocloak.AuthenticatorConfigRepresentation, error)
	GetRequiredActions(context.Context, string, string) ([]*gocloak.RequiredActionProviderRepresentation, error)
	GetRequiredAction(context.Context, string, string, string) (*gocloak.RequiredActionProviderRepresentation, error)
	GetUnregisteredRequiredActions(context.Context, string, string) ([]*gocloak.UnregisteredRequiredActionProviderRepresentation, error)
	GetIdentityProviders(context.Context, string, string) ([]*gocloak.IdentityProviderRepresentation, error)
	GetIdentityProvider(context.Context, string, string, string) (*gocloak.IdentityProviderRepresentation, error)
	GetIdentityProviderMappers(context.Context, string, string, string) ([]*gocloak.IdentityProviderMapper, error)
	GetIdentityProviderMapperByID(context.Context, string, string, string, string) (*gocloak.IdentityProviderMapper, error)

	// Organizations (Keycloak 26+)
	GetOrganizations(context.Context, string, string, gocloak.GetOrganizationsParams) ([]*gocloak.OrganizationRepresentation, error)
	GetOrganizationByID(context.Context, string, string, string) (*gocloak.OrganizationRepresentation, error)
	GetOrganizationCount(context.Context, string, string, gocloak.GetOrganizationCountParams) (int64, error)
	GetOrganizationMembers(context.Context, string, string, string, gocloak.GetMembersParams) ([]*gocloak.MemberRepresentation, error)
	GetOrganizationMemberCount(context.Context, string, string, string) (int, error)
	GetOrganizationMemberByID(context.Context, string, string, string, string) (*gocloak.MemberRepresentation, error)
	GetMemberAssociatedOrganizations(context.Context, string, string, string, bool) ([]*gocloak.OrganizationRepresentation, error)
	GetOrganizationIdentityProviders(context.Context, string, string, string) ([]*gocloak.IdentityProviderRepresentation, error)
	GetOrganizationInvitations(context.Context, string, string, string, gocloak.GetOrganizationInvitationsParams) ([]*gocloak.OrganizationInvitationRepresentation, error)
	GetOrganizationGroups(context.Context, string, string, string, gocloak.GetOrganizationGroupsParams) ([]*gocloak.Group, error)

	// Components / User Federation
	GetComponentsWithParams(context.Context, string, string, gocloak.GetComponentsParams) ([]*gocloak.Component, error)
	GetComponent(context.Context, string, string, string) (*gocloak.Component, error)

	// Fine-Grained Authorization Services
	GetResourceServer(context.Context, string, string, string) (*gocloak.ResourceServerRepresentation, error)
	GetResources(context.Context, string, string, string, gocloak.GetResourceParams) ([]*gocloak.ResourceRepresentation, error)
	GetResource(context.Context, string, string, string, string) (*gocloak.ResourceRepresentation, error)
	GetScopes(context.Context, string, string, string, gocloak.GetScopeParams) ([]*gocloak.ScopeRepresentation, error)
	GetScope(context.Context, string, string, string, string) (*gocloak.ScopeRepresentation, error)
	GetPolicies(context.Context, string, string, string, gocloak.GetPolicyParams) ([]*gocloak.PolicyRepresentation, error)
	GetPolicy(context.Context, string, string, string, string) (*gocloak.PolicyRepresentation, error)
	GetPermissions(context.Context, string, string, string, gocloak.GetPermissionParams) ([]*gocloak.PermissionRepresentation, error)
	GetPermission(context.Context, string, string, string, string) (*gocloak.PermissionRepresentation, error)
	GetAuthorizationPolicyAssociatedPolicies(context.Context, string, string, string, string) ([]*gocloak.PolicyRepresentation, error)
	GetAuthorizationPolicyResources(context.Context, string, string, string, string) ([]*gocloak.PolicyResourceRepresentation, error)
	GetAuthorizationPolicyScopes(context.Context, string, string, string, string) ([]*gocloak.PolicyScopeRepresentation, error)
}
