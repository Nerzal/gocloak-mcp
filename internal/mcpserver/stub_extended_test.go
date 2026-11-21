package mcpserver

import (
	"context"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

func (s *stubService) GetUserOfflineSessions(context.Context, string, string, string) ([]keycloak.UserSession, error) {
	return []keycloak.UserSession{{ID: "os1"}}, s.err
}

func (s *stubService) GetUserCredentials(context.Context, string, string) ([]keycloak.UserCredentialInfo, error) {
	return []keycloak.UserCredentialInfo{{ID: "cr1", Type: "otp"}}, s.err
}

func (s *stubService) GetUserFederatedIdentities(context.Context, string, string) ([]keycloak.FederatedIdentityInfo, error) {
	return []keycloak.FederatedIdentityInfo{{IdentityProvider: "google", UserID: "g1"}}, s.err
}

func (s *stubService) GetUserBruteForceStatus(context.Context, string, string) (keycloak.BruteForceStatusInfo, error) {
	return keycloak.BruteForceStatusInfo{NumFailures: 1, Disabled: false}, s.err
}

func (s *stubService) GetUserCompositeRealmRoles(context.Context, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r1", Name: "viewer"}}, s.err
}

func (s *stubService) GetUserCompositeClientRoles(context.Context, string, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "cr1", Name: "read"}}, s.err
}

func (s *stubService) GetUserAvailableRealmRoles(context.Context, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r2", Name: "editor"}}, s.err
}

func (s *stubService) GetUserAvailableClientRoles(context.Context, string, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "cr2", Name: "write"}}, s.err
}

func (s *stubService) GetClientRole(context.Context, string, string, string) (keycloak.RoleInfo, error) {
	return keycloak.RoleInfo{ID: "cr1", Name: "read"}, s.err
}

func (s *stubService) GetClientProtocolMappers(context.Context, string, string) ([]keycloak.ProtocolMapperInfo, error) {
	return []keycloak.ProtocolMapperInfo{{ID: "pm1", Name: "org"}}, s.err
}

func (s *stubService) GetClientDefaultScopes(context.Context, string, string) ([]keycloak.ClientScopeInfo, error) {
	return []keycloak.ClientScopeInfo{{ID: "sc1", Name: "email"}}, s.err
}

func (s *stubService) GetClientOptionalScopes(context.Context, string, string) ([]keycloak.ClientScopeInfo, error) {
	return []keycloak.ClientScopeInfo{{ID: "sc2", Name: "address"}}, s.err
}

func (s *stubService) GetClientScopeMappings(context.Context, string, string) (keycloak.RoleMappings, error) {
	return keycloak.RoleMappings{RealmRoles: []keycloak.RoleInfo{{ID: "r1", Name: "viewer"}}}, s.err
}

func (s *stubService) GetClientSessions(context.Context, string, string, int, int) ([]keycloak.UserSession, error) {
	return []keycloak.UserSession{{ID: "s1"}}, s.err
}

func (s *stubService) GetClientOfflineSessions(context.Context, string, string, int, int) ([]keycloak.UserSession, error) {
	return []keycloak.UserSession{{ID: "os1"}}, s.err
}

func (s *stubService) ListClientScopeProtocolMappers(context.Context, string, string) ([]keycloak.ProtocolMapperInfo, error) {
	return []keycloak.ProtocolMapperInfo{{ID: "pm1", Name: "org"}}, s.err
}

func (s *stubService) GetClientScopeProtocolMapper(context.Context, string, string, string) (keycloak.ProtocolMapperInfo, error) {
	return keycloak.ProtocolMapperInfo{ID: "pm1", Name: "org"}, s.err
}

func (s *stubService) GetDefaultDefaultClientScopes(context.Context, string) ([]keycloak.ClientScopeInfo, error) {
	return []keycloak.ClientScopeInfo{{ID: "sc1", Name: "email"}}, s.err
}

func (s *stubService) GetDefaultOptionalClientScopes(context.Context, string) ([]keycloak.ClientScopeInfo, error) {
	return []keycloak.ClientScopeInfo{{ID: "sc2", Name: "address"}}, s.err
}

func (s *stubService) GetClientScopeRealmRoles(context.Context, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r1", Name: "viewer"}}, s.err
}

func (s *stubService) GetClientScopeClientRoles(context.Context, string, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "cr1", Name: "read"}}, s.err
}

func (s *stubService) GetRoleByID(context.Context, string, string) (keycloak.RoleInfo, error) {
	return keycloak.RoleInfo{ID: "r1", Name: "viewer"}, s.err
}

func (s *stubService) GetRealmRoleComposites(context.Context, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r2", Name: "child"}}, s.err
}

func (s *stubService) GetRoleCompositesByID(context.Context, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r2", Name: "child"}}, s.err
}

func (s *stubService) GetGroupsInRole(context.Context, string, string) ([]keycloak.GroupInfo, error) {
	return []keycloak.GroupInfo{{ID: "g1", Name: "devs"}}, s.err
}

func (s *stubService) GetGroupsInClientRole(context.Context, string, string, string) ([]keycloak.GroupInfo, error) {
	return []keycloak.GroupInfo{{ID: "g1", Name: "devs"}}, s.err
}

func (s *stubService) GetGroupByPath(context.Context, string, string) (keycloak.GroupInfo, error) {
	return keycloak.GroupInfo{ID: "g1", Name: "devs", Path: "/eng/devs"}, s.err
}

func (s *stubService) ListChildGroups(context.Context, string, string, int, int, string) ([]keycloak.GroupInfo, error) {
	return []keycloak.GroupInfo{{ID: "g2", Name: "backend"}}, s.err
}

func (s *stubService) GetDefaultGroups(context.Context, string) ([]keycloak.GroupInfo, error) {
	return []keycloak.GroupInfo{{ID: "g1", Name: "devs"}}, s.err
}

func (s *stubService) GetGroupCompositeRealmRoles(context.Context, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r1", Name: "viewer"}}, s.err
}

func (s *stubService) GetGroupCompositeClientRoles(context.Context, string, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "cr1", Name: "read"}}, s.err
}

func (s *stubService) GetGroupAvailableRealmRoles(context.Context, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r2", Name: "editor"}}, s.err
}

func (s *stubService) GetGroupAvailableClientRoles(context.Context, string, string, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "cr2", Name: "write"}}, s.err
}

func (s *stubService) GetRealmKeys(context.Context, string) (keycloak.RealmKeysInfo, error) {
	return keycloak.RealmKeysInfo{ActiveRS256: "k1", Keys: []keycloak.RealmKeyInfo{{Kid: "k1"}}}, s.err
}

func (s *stubService) GetRealmCerts(context.Context, string) ([]keycloak.JWKInfo, error) {
	return []keycloak.JWKInfo{{Kid: "k1", Kty: "RSA"}}, s.err
}

func (s *stubService) GetRealmIssuer(context.Context, string) (keycloak.RealmIssuerInfo, error) {
	return keycloak.RealmIssuerInfo{Realm: "example"}, s.err
}

func (s *stubService) GetUserProfileConfig(context.Context, string) (keycloak.UserProfileConfigInfo, error) {
	return keycloak.UserProfileConfigInfo{Attributes: []keycloak.UserProfileAttributeInfo{{Name: "email"}}}, s.err
}

func (s *stubService) GetServerInfo(context.Context) (keycloak.ServerInfo, error) {
	return keycloak.ServerInfo{Version: "26.1.0"}, s.err
}

func (s *stubService) GetAuthenticationFlow(context.Context, string, string) (keycloak.AuthFlowInfo, error) {
	return keycloak.AuthFlowInfo{ID: "f1", Alias: "browser"}, s.err
}

func (s *stubService) GetAuthenticatorConfig(context.Context, string, string) (keycloak.AuthenticatorConfigInfo, error) {
	return keycloak.AuthenticatorConfigInfo{ID: "ac1", Alias: "cfg"}, s.err
}

func (s *stubService) GetRequiredAction(context.Context, string, string) (keycloak.RequiredActionInfo, error) {
	return keycloak.RequiredActionInfo{Alias: "CONFIGURE_TOTP"}, s.err
}

func (s *stubService) ListUnregisteredRequiredActions(context.Context, string) ([]keycloak.UnregisteredRequiredActionInfo, error) {
	return []keycloak.UnregisteredRequiredActionInfo{{ProviderID: "webauthn-register"}}, s.err
}

func (s *stubService) ListIdentityProviderMappers(context.Context, string, string) ([]keycloak.IdentityProviderMapperInfo, error) {
	return []keycloak.IdentityProviderMapperInfo{{ID: "im1", Name: "m1"}}, s.err
}

func (s *stubService) GetIdentityProviderMapper(context.Context, string, string, string) (keycloak.IdentityProviderMapperInfo, error) {
	return keycloak.IdentityProviderMapperInfo{ID: "im1", Name: "m1"}, s.err
}

func (s *stubService) GetOrganization(context.Context, string, string) (keycloak.OrganizationInfo, error) {
	return keycloak.OrganizationInfo{ID: "o1", Name: "Acme"}, s.err
}

func (s *stubService) CountOrganizations(context.Context, string, string) (int64, error) {
	return 1, s.err
}

func (s *stubService) CountOrganizationMembers(context.Context, string, string) (int, error) {
	return 2, s.err
}

func (s *stubService) GetOrganizationMember(context.Context, string, string, string) (keycloak.OrganizationMember, error) {
	return keycloak.OrganizationMember{User: keycloak.User{ID: "u1"}}, s.err
}

func (s *stubService) GetUserOrganizations(context.Context, string, string) ([]keycloak.OrganizationInfo, error) {
	return []keycloak.OrganizationInfo{{ID: "o1", Name: "Acme"}}, s.err
}

func (s *stubService) ListOrganizationIdentityProviders(context.Context, string, string) ([]keycloak.IdentityProviderInfo, error) {
	return []keycloak.IdentityProviderInfo{{Alias: "okta"}}, s.err
}

func (s *stubService) ListOrganizationInvitations(context.Context, string, string, int, int, string) ([]keycloak.OrganizationInvitationInfo, error) {
	return []keycloak.OrganizationInvitationInfo{{ID: "inv1", Email: "bob@acme.test"}}, s.err
}

func (s *stubService) ListOrganizationGroups(context.Context, string, string, int, int, string) ([]keycloak.GroupInfo, error) {
	return []keycloak.GroupInfo{{ID: "g1", Name: "org-admins"}}, s.err
}

func (s *stubService) ListComponents(context.Context, string, keycloak.ComponentFilter) ([]keycloak.ComponentInfo, error) {
	return []keycloak.ComponentInfo{{ID: "cmp1", Name: "ldap"}}, s.err
}

func (s *stubService) GetComponent(context.Context, string, string) (keycloak.ComponentInfo, error) {
	return keycloak.ComponentInfo{ID: "cmp1", Name: "ldap"}, s.err
}

func (s *stubService) GetResourceServer(context.Context, string, string) (keycloak.ResourceServerInfo, error) {
	return keycloak.ResourceServerInfo{ID: "rs1", ClientID: "c1"}, s.err
}

func (s *stubService) ListAuthzResources(context.Context, string, string, int, int, *keycloak.AuthzResourceFilter) ([]keycloak.AuthzResourceInfo, error) {
	return []keycloak.AuthzResourceInfo{{ID: "res1", Name: "docs"}}, s.err
}

func (s *stubService) GetAuthzResource(context.Context, string, string, string) (keycloak.AuthzResourceInfo, error) {
	return keycloak.AuthzResourceInfo{ID: "res1", Name: "docs"}, s.err
}

func (s *stubService) ListAuthzScopes(context.Context, string, string, int, int, string) ([]keycloak.AuthzScopeInfo, error) {
	return []keycloak.AuthzScopeInfo{{ID: "as1", Name: "read"}}, s.err
}

func (s *stubService) GetAuthzScope(context.Context, string, string, string) (keycloak.AuthzScopeInfo, error) {
	return keycloak.AuthzScopeInfo{ID: "as1", Name: "read"}, s.err
}

func (s *stubService) ListAuthzPolicies(context.Context, string, string, int, int, keycloak.AuthzPolicyFilter) ([]keycloak.AuthzPolicyInfo, error) {
	return []keycloak.AuthzPolicyInfo{{ID: "pol1", Name: "admins"}}, s.err
}

func (s *stubService) GetAuthzPolicy(context.Context, string, string, string) (keycloak.AuthzPolicyInfo, error) {
	return keycloak.AuthzPolicyInfo{ID: "pol1", Name: "admins"}, s.err
}

func (s *stubService) ListAuthzPermissions(context.Context, string, string, int, int, keycloak.AuthzPermissionFilter) ([]keycloak.AuthzPermissionInfo, error) {
	return []keycloak.AuthzPermissionInfo{{ID: "perm1", Name: "docs-read"}}, s.err
}

func (s *stubService) GetAuthzPermission(context.Context, string, string, string) (keycloak.AuthzPermissionInfo, error) {
	return keycloak.AuthzPermissionInfo{ID: "perm1", Name: "docs-read"}, s.err
}

func (s *stubService) GetPolicyAssociatedPolicies(context.Context, string, string, string) ([]keycloak.AuthzPolicyInfo, error) {
	return []keycloak.AuthzPolicyInfo{{ID: "pol2", Name: "sub"}}, s.err
}

func (s *stubService) GetPolicyResources(context.Context, string, string, string) ([]keycloak.NamedRef, error) {
	return []keycloak.NamedRef{{ID: "res1", Name: "docs"}}, s.err
}

func (s *stubService) GetPolicyScopes(context.Context, string, string, string) ([]keycloak.NamedRef, error) {
	return []keycloak.NamedRef{{ID: "as1", Name: "read"}}, s.err
}
