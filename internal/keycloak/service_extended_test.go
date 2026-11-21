package keycloak

import (
	"context"
	"testing"

	"github.com/Nerzal/gocloak/v15"
)

func (c *stubClient) GetUserOfflineSessionsForClient(_ context.Context, _, realm, _, _ string) ([]*gocloak.UserSessionRepresentation, error) {
	c.lastRealm = realm
	return c.sessions, c.err
}

func (c *stubClient) GetCredentials(_ context.Context, _, realm, _ string) ([]*gocloak.CredentialRepresentation, error) {
	c.lastRealm = realm
	return c.creds, c.err
}

func (c *stubClient) GetUserFederatedIdentities(_ context.Context, _, realm, _ string) ([]*gocloak.FederatedIdentityRepresentation, error) {
	c.lastRealm = realm
	return c.fedIDs, c.err
}

func (c *stubClient) GetUserBruteForceDetectionStatus(_ context.Context, _, realm, _ string) (*gocloak.BruteForceStatus, error) {
	c.lastRealm = realm
	return c.bruteForce, c.err
}

func (c *stubClient) GetCompositeRealmRolesByUserID(_ context.Context, _, realm, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetCompositeClientRolesByUserID(_ context.Context, _, realm, _, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetAvailableRealmRolesByUserID(_ context.Context, _, realm, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetAvailableClientRolesByUserID(_ context.Context, _, realm, _, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetClientRole(_ context.Context, _, realm, _, _ string) (*gocloak.Role, error) {
	c.lastRealm = realm
	return c.role, c.err
}

func (c *stubClient) GetClientsDefaultScopes(_ context.Context, _, realm, _ string) ([]*gocloak.ClientScope, error) {
	c.lastRealm = realm
	return c.scopes, c.err
}

func (c *stubClient) GetClientsOptionalScopes(_ context.Context, _, realm, _ string) ([]*gocloak.ClientScope, error) {
	c.lastRealm = realm
	return c.scopes, c.err
}

func (c *stubClient) GetClientScopeMappings(_ context.Context, _, realm, _ string) (*gocloak.MappingsRepresentation, error) {
	c.lastRealm = realm
	return c.mappings, c.err
}

func (c *stubClient) GetClientUserSessions(_ context.Context, _, realm, _ string, _ ...gocloak.GetClientUserSessionsParams) ([]*gocloak.UserSessionRepresentation, error) {
	c.lastRealm = realm
	return c.sessions, c.err
}

func (c *stubClient) GetClientOfflineSessions(_ context.Context, _, realm, _ string, _ ...gocloak.GetClientUserSessionsParams) ([]*gocloak.UserSessionRepresentation, error) {
	c.lastRealm = realm
	return c.sessions, c.err
}

func (c *stubClient) GetClientScopeProtocolMappers(_ context.Context, _, realm, _ string) ([]*gocloak.ProtocolMappers, error) {
	c.lastRealm = realm
	return c.scopeMappers, c.err
}

func (c *stubClient) GetClientScopeProtocolMapper(_ context.Context, _, realm, _, _ string) (*gocloak.ProtocolMappers, error) {
	c.lastRealm = realm
	return c.scopeMapper, c.err
}

func (c *stubClient) GetDefaultDefaultClientScopes(_ context.Context, _, realm string) ([]*gocloak.ClientScope, error) {
	c.lastRealm = realm
	return c.scopes, c.err
}

func (c *stubClient) GetDefaultOptionalClientScopes(_ context.Context, _, realm string) ([]*gocloak.ClientScope, error) {
	c.lastRealm = realm
	return c.scopes, c.err
}

func (c *stubClient) GetClientScopesScopeMappingsRealmRoles(_ context.Context, _, realm, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetClientScopesScopeMappingsClientRoles(_ context.Context, _, realm, _, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetRealmRoleByID(_ context.Context, _, realm, _ string) (*gocloak.Role, error) {
	c.lastRealm = realm
	return c.role, c.err
}

func (c *stubClient) GetCompositeRealmRoles(_ context.Context, _, realm, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetCompositeRolesByRoleID(_ context.Context, _, realm, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetGroupsByRole(_ context.Context, _, realm, _ string) ([]*gocloak.Group, error) {
	c.lastRealm = realm
	return c.groups, c.err
}

func (c *stubClient) GetGroupsByClientRole(_ context.Context, _, realm, _, _ string) ([]*gocloak.Group, error) {
	c.lastRealm = realm
	return c.groups, c.err
}

func (c *stubClient) GetGroupByPath(_ context.Context, _, realm, _ string) (*gocloak.Group, error) {
	c.lastRealm = realm
	return c.group, c.err
}

func (c *stubClient) GetChildGroups(_ context.Context, _, realm, _ string, _ gocloak.GetChildGroupsParams) ([]*gocloak.Group, error) {
	c.lastRealm = realm
	return c.groups, c.err
}

func (c *stubClient) GetDefaultGroups(_ context.Context, _, realm string) ([]*gocloak.Group, error) {
	c.lastRealm = realm
	return c.groups, c.err
}

func (c *stubClient) GetCompositeRealmRolesByGroupID(_ context.Context, _, realm, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetCompositeClientRolesByGroupID(_ context.Context, _, realm, _, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetAvailableRealmRolesByGroupID(_ context.Context, _, realm, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetAvailableClientRolesByGroupID(_ context.Context, _, realm, _, _ string) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetKeyStoreConfig(_ context.Context, _, realm string) (*gocloak.KeyStoreConfig, error) {
	c.lastRealm = realm
	return c.keyStore, c.err
}

func (c *stubClient) GetCerts(_ context.Context, realm string) (*gocloak.CertResponse, error) {
	c.lastRealm = realm
	return c.certs, c.err
}

func (c *stubClient) GetIssuer(_ context.Context, realm string) (*gocloak.IssuerResponse, error) {
	c.lastRealm = realm
	return c.issuer, c.err
}

func (c *stubClient) GetUserProfileConfig(_ context.Context, _, realm string) (*gocloak.UserProfileConfig, error) {
	c.lastRealm = realm
	return c.userProfile, c.err
}

func (c *stubClient) GetServerInfo(_ context.Context, _ string) (*gocloak.ServerInfoRepresentation, error) {
	return c.serverInfo, c.err
}

func (c *stubClient) GetAuthenticationFlow(_ context.Context, _, realm, _ string) (*gocloak.AuthenticationFlowRepresentation, error) {
	c.lastRealm = realm
	return c.flow, c.err
}

func (c *stubClient) GetAuthenticatorConfig(_ context.Context, _, realm, _ string) (*gocloak.AuthenticatorConfigRepresentation, error) {
	c.lastRealm = realm
	return c.authConfig, c.err
}

func (c *stubClient) GetRequiredAction(_ context.Context, _, realm, _ string) (*gocloak.RequiredActionProviderRepresentation, error) {
	c.lastRealm = realm
	return c.action, c.err
}

func (c *stubClient) GetUnregisteredRequiredActions(_ context.Context, _, realm string) ([]*gocloak.UnregisteredRequiredActionProviderRepresentation, error) {
	c.lastRealm = realm
	return c.unregActions, c.err
}

func (c *stubClient) GetIdentityProviderMappers(_ context.Context, _, realm, _ string) ([]*gocloak.IdentityProviderMapper, error) {
	c.lastRealm = realm
	return c.idpMappers, c.err
}

func (c *stubClient) GetIdentityProviderMapperByID(_ context.Context, _, realm, _, _ string) (*gocloak.IdentityProviderMapper, error) {
	c.lastRealm = realm
	return c.idpMapper, c.err
}

func (c *stubClient) GetOrganizationByID(_ context.Context, _, realm, _ string) (*gocloak.OrganizationRepresentation, error) {
	c.lastRealm = realm
	return c.org, c.err
}

func (c *stubClient) GetOrganizationCount(_ context.Context, _, realm string, _ gocloak.GetOrganizationCountParams) (int64, error) {
	c.lastRealm = realm
	return c.orgCount, c.err
}

func (c *stubClient) GetOrganizationMemberCount(_ context.Context, _, realm, _ string) (int, error) {
	c.lastRealm = realm
	return c.orgMemberCount, c.err
}

func (c *stubClient) GetOrganizationMemberByID(_ context.Context, _, realm, _, _ string) (*gocloak.MemberRepresentation, error) {
	c.lastRealm = realm
	return c.orgMember, c.err
}

func (c *stubClient) GetMemberAssociatedOrganizations(_ context.Context, _, realm, _ string, _ bool) ([]*gocloak.OrganizationRepresentation, error) {
	c.lastRealm = realm
	return c.orgs, c.err
}

func (c *stubClient) GetOrganizationIdentityProviders(_ context.Context, _, realm, _ string) ([]*gocloak.IdentityProviderRepresentation, error) {
	c.lastRealm = realm
	return c.idps, c.err
}

//nolint:gocritic // GoCloak's interface requires GetOrganizationInvitationsParams by value.
func (c *stubClient) GetOrganizationInvitations(_ context.Context, _, realm, _ string, _ gocloak.GetOrganizationInvitationsParams) ([]*gocloak.OrganizationInvitationRepresentation, error) {
	c.lastRealm = realm
	return c.invitations, c.err
}

//nolint:gocritic // GoCloak's interface requires GetOrganizationGroupsParams by value.
func (c *stubClient) GetOrganizationGroups(_ context.Context, _, realm, _ string, _ gocloak.GetOrganizationGroupsParams) ([]*gocloak.Group, error) {
	c.lastRealm = realm
	return c.groups, c.err
}

func (c *stubClient) GetComponentsWithParams(_ context.Context, _, realm string, _ gocloak.GetComponentsParams) ([]*gocloak.Component, error) {
	c.lastRealm = realm
	return c.components, c.err
}

func (c *stubClient) GetComponent(_ context.Context, _, realm, _ string) (*gocloak.Component, error) {
	c.lastRealm = realm
	return c.component, c.err
}

func (c *stubClient) GetResourceServer(_ context.Context, _, realm, _ string) (*gocloak.ResourceServerRepresentation, error) {
	c.lastRealm = realm
	return c.resourceServer, c.err
}

//nolint:gocritic // GoCloak's interface requires GetResourceParams by value.
func (c *stubClient) GetResources(_ context.Context, _, realm, _ string, _ gocloak.GetResourceParams) ([]*gocloak.ResourceRepresentation, error) {
	c.lastRealm = realm
	return c.authzResources, c.err
}

func (c *stubClient) GetResource(_ context.Context, _, realm, _, _ string) (*gocloak.ResourceRepresentation, error) {
	c.lastRealm = realm
	return c.authzResource, c.err
}

func (c *stubClient) GetScopes(_ context.Context, _, realm, _ string, _ gocloak.GetScopeParams) ([]*gocloak.ScopeRepresentation, error) {
	c.lastRealm = realm
	return c.authzScopes, c.err
}

func (c *stubClient) GetScope(_ context.Context, _, realm, _, _ string) (*gocloak.ScopeRepresentation, error) {
	c.lastRealm = realm
	return c.authzScope, c.err
}

func (c *stubClient) GetPolicies(_ context.Context, _, realm, _ string, _ gocloak.GetPolicyParams) ([]*gocloak.PolicyRepresentation, error) {
	c.lastRealm = realm
	return c.authzPolicies, c.err
}

func (c *stubClient) GetPolicy(_ context.Context, _, realm, _, _ string) (*gocloak.PolicyRepresentation, error) {
	c.lastRealm = realm
	return c.authzPolicy, c.err
}

func (c *stubClient) GetPermissions(_ context.Context, _, realm, _ string, _ gocloak.GetPermissionParams) ([]*gocloak.PermissionRepresentation, error) {
	c.lastRealm = realm
	return c.authzPermissions, c.err
}

func (c *stubClient) GetPermission(_ context.Context, _, realm, _, _ string) (*gocloak.PermissionRepresentation, error) {
	c.lastRealm = realm
	return c.authzPermission, c.err
}

func (c *stubClient) GetAuthorizationPolicyAssociatedPolicies(_ context.Context, _, realm, _, _ string) ([]*gocloak.PolicyRepresentation, error) {
	c.lastRealm = realm
	return c.authzPolicies, c.err
}

func (c *stubClient) GetAuthorizationPolicyResources(_ context.Context, _, realm, _, _ string) ([]*gocloak.PolicyResourceRepresentation, error) {
	c.lastRealm = realm
	return c.policyResources, c.err
}

func (c *stubClient) GetAuthorizationPolicyScopes(_ context.Context, _, realm, _, _ string) ([]*gocloak.PolicyScopeRepresentation, error) {
	c.lastRealm = realm
	return c.policyScopes, c.err
}

func newExtendedFixtureService() Service {
	return NewService(&stubClient{
		users:            []*gocloak.User{{ID: strP("u1"), Username: strP("alice"), Enabled: boolP(true)}},
		sessions:         []*gocloak.UserSessionRepresentation{{ID: "s1", UserID: "u1"}},
		creds:            []*gocloak.CredentialRepresentation{{ID: strP("cr1"), Type: strP("otp"), UserLabel: strP("phone")}},
		fedIDs:           []*gocloak.FederatedIdentityRepresentation{{IdentityProvider: "google", UserID: "g1", UserName: "alice"}},
		bruteForce:       &gocloak.BruteForceStatus{NumFailures: 3, Disabled: true, LastIPFailure: "127.0.0.1"},
		roles:            []*gocloak.Role{{ID: strP("r1"), Name: strP("viewer")}},
		role:             &gocloak.Role{ID: strP("r1"), Name: strP("viewer")},
		groups:           []*gocloak.Group{{ID: strP("g1"), Name: strP("devs"), Path: strP("/eng/devs")}},
		group:            &gocloak.Group{ID: strP("g1"), Name: strP("devs"), Path: strP("/eng/devs")},
		scopes:           []*gocloak.ClientScope{{ID: strP("sc1"), Name: strP("email")}},
		mappings:         &gocloak.MappingsRepresentation{RealmMappings: []gocloak.Role{{ID: strP("r1"), Name: strP("viewer")}}},
		client:           &gocloak.Client{ID: strP("c1"), ClientID: strP("web"), ProtocolMappers: []gocloak.ProtocolMapperRepresentation{{ID: strP("pm1"), Name: strP("org"), Config: map[string]string{"claim.name": "org"}}}},
		scopeMappers:     []*gocloak.ProtocolMappers{{ID: strP("pm1"), Name: strP("org"), ProtocolMappersConfig: gocloak.ProtocolMappersConfig{ClaimName: strP("org")}}},
		scopeMapper:      &gocloak.ProtocolMappers{ID: strP("pm1"), Name: strP("org")},
		keyStore:         &gocloak.KeyStoreConfig{ActiveKeys: gocloak.ActiveKeys{RS256: "k1"}, Key: []gocloak.Key{{Kid: "k1", Algorithm: "RS256"}}},
		certs:            &gocloak.CertResponse{Keys: []gocloak.CertResponseKey{{Kid: "k1", Kty: "RSA"}}},
		issuer:           &gocloak.IssuerResponse{Realm: "primary", PublicKey: "pub"},
		userProfile:      &gocloak.UserProfileConfig{Attributes: []gocloak.UserProfileAttribute{{Name: strP("email")}}, Groups: []gocloak.UserProfileGroup{{Name: strP("contact")}}},
		serverInfo:       &gocloak.ServerInfoRepresentation{SystemInfo: gocloak.SystemInfoRepresentation{Version: "26.1.0"}},
		flow:             &gocloak.AuthenticationFlowRepresentation{ID: strP("f1"), Alias: strP("browser")},
		authConfig:       &gocloak.AuthenticatorConfigRepresentation{ID: strP("ac1"), Alias: strP("cfg"), Config: map[string]string{"max": "5"}},
		action:           &gocloak.RequiredActionProviderRepresentation{Alias: strP("CONFIGURE_TOTP"), Enabled: boolP(true)},
		unregActions:     []*gocloak.UnregisteredRequiredActionProviderRepresentation{{Name: "WebAuthn", ProviderID: "webauthn-register"}},
		idps:             []*gocloak.IdentityProviderRepresentation{{Alias: strP("okta"), Enabled: boolP(true)}},
		idpMappers:       []*gocloak.IdentityProviderMapper{{ID: strP("im1"), Name: strP("m1"), Config: map[string]string{"claim": "groups"}}},
		idpMapper:        &gocloak.IdentityProviderMapper{ID: strP("im1"), Name: strP("m1")},
		orgs:             []*gocloak.OrganizationRepresentation{{ID: strP("o1"), Name: strP("Acme")}},
		org:              &gocloak.OrganizationRepresentation{ID: strP("o1"), Name: strP("Acme")},
		orgCount:         2,
		orgMemberCount:   5,
		orgMember:        &gocloak.MemberRepresentation{User: gocloak.User{ID: strP("u1")}, MembershipType: gocloak.MembershipType("MANAGED")},
		invitations:      []*gocloak.OrganizationInvitationRepresentation{{ID: "inv1", Email: "bob@acme.test"}},
		components:       []*gocloak.Component{{ID: strP("cmp1"), Name: strP("ldap")}},
		component:        &gocloak.Component{ID: strP("cmp1"), Name: strP("ldap")},
		resourceServer:   &gocloak.ResourceServerRepresentation{ID: strP("rs1"), ClientID: strP("c1")},
		authzResources:   []*gocloak.ResourceRepresentation{{ID: strP("res1"), Name: strP("docs")}},
		authzResource:    &gocloak.ResourceRepresentation{ID: strP("res1"), Name: strP("docs")},
		authzScopes:      []*gocloak.ScopeRepresentation{{ID: strP("as1"), Name: strP("read")}},
		authzScope:       &gocloak.ScopeRepresentation{ID: strP("as1"), Name: strP("read")},
		authzPolicies:    []*gocloak.PolicyRepresentation{{ID: strP("pol1"), Name: strP("admins")}},
		authzPolicy:      &gocloak.PolicyRepresentation{ID: strP("pol1"), Name: strP("admins")},
		authzPermissions: []*gocloak.PermissionRepresentation{{ID: strP("perm1"), Name: strP("docs-read")}},
		authzPermission:  &gocloak.PermissionRepresentation{ID: strP("perm1"), Name: strP("docs-read")},
		policyResources:  []*gocloak.PolicyResourceRepresentation{{ID: "res1", Name: "docs"}},
		policyScopes:     []*gocloak.PolicyScopeRepresentation{{ID: "as1", Name: "read"}},
	}, &stubTokenProvider{}, "primary", []string{"primary"})
}

func TestExtendedUserAndRoleListServiceMethods(t *testing.T) {
	ctx := context.Background()
	svc := newExtendedFixtureService()

	creds, err := svc.GetUserCredentials(ctx, "", "u1")
	requireOK(t, err, "GetUserCredentials")
	requireCount(t, len(creds), 1, "GetUserCredentials")

	feds, err := svc.GetUserFederatedIdentities(ctx, "", "u1")
	requireOK(t, err, "GetUserFederatedIdentities")
	requireCount(t, len(feds), 1, "GetUserFederatedIdentities")

	off, err := svc.GetUserOfflineSessions(ctx, "", "u1", "c1")
	requireOK(t, err, "GetUserOfflineSessions")
	requireCount(t, len(off), 1, "GetUserOfflineSessions")

	bf, err := svc.GetUserBruteForceStatus(ctx, "", "u1")
	requireOK(t, err, "GetUserBruteForceStatus")
	if !bf.Disabled || bf.NumFailures != 3 {
		t.Fatalf("GetUserBruteForceStatus = %+v", bf)
	}

	for name, call := range map[string]func() ([]RoleInfo, error){
		"GetUserCompositeRealmRoles":   func() ([]RoleInfo, error) { return svc.GetUserCompositeRealmRoles(ctx, "", "u1") },
		"GetUserCompositeClientRoles":  func() ([]RoleInfo, error) { return svc.GetUserCompositeClientRoles(ctx, "", "u1", "c1") },
		"GetUserAvailableRealmRoles":   func() ([]RoleInfo, error) { return svc.GetUserAvailableRealmRoles(ctx, "", "u1") },
		"GetUserAvailableClientRoles":  func() ([]RoleInfo, error) { return svc.GetUserAvailableClientRoles(ctx, "", "u1", "c1") },
		"GetRealmRoleComposites":       func() ([]RoleInfo, error) { return svc.GetRealmRoleComposites(ctx, "", "viewer") },
		"GetRoleCompositesByID":        func() ([]RoleInfo, error) { return svc.GetRoleCompositesByID(ctx, "", "r1") },
		"GetClientScopeRealmRoles":     func() ([]RoleInfo, error) { return svc.GetClientScopeRealmRoles(ctx, "", "sc1") },
		"GetClientScopeClientRoles":    func() ([]RoleInfo, error) { return svc.GetClientScopeClientRoles(ctx, "", "sc1", "c1") },
		"GetGroupCompositeRealmRoles":  func() ([]RoleInfo, error) { return svc.GetGroupCompositeRealmRoles(ctx, "", "g1") },
		"GetGroupCompositeClientRoles": func() ([]RoleInfo, error) { return svc.GetGroupCompositeClientRoles(ctx, "", "g1", "c1") },
		"GetGroupAvailableRealmRoles":  func() ([]RoleInfo, error) { return svc.GetGroupAvailableRealmRoles(ctx, "", "g1") },
		"GetGroupAvailableClientRoles": func() ([]RoleInfo, error) { return svc.GetGroupAvailableClientRoles(ctx, "", "g1", "c1") },
	} {
		roles, callErr := call()
		requireOK(t, callErr, name)
		requireCount(t, len(roles), 1, name)
	}
}

func TestExtendedClientServiceMethods(t *testing.T) {
	ctx := context.Background()
	svc := newExtendedFixtureService()

	for name, call := range map[string]func(){
		"GetClientRole": func() { _, err := svc.GetClientRole(ctx, "", "c1", "viewer"); requireOK(t, err, "GetClientRole") },
		"GetClientProtocolMappers": func() {
			_, err := svc.GetClientProtocolMappers(ctx, "", "c1")
			requireOK(t, err, "GetClientProtocolMappers")
		},
		"ListClientScopeProtocolMappers": func() {
			_, err := svc.ListClientScopeProtocolMappers(ctx, "", "sc1")
			requireOK(t, err, "ListClientScopeProtocolMappers")
		},
		"GetClientScopeProtocolMapper": func() {
			_, err := svc.GetClientScopeProtocolMapper(ctx, "", "sc1", "pm1")
			requireOK(t, err, "GetClientScopeProtocolMapper")
		},
		"GetClientDefaultScopes": func() {
			_, err := svc.GetClientDefaultScopes(ctx, "", "c1")
			requireOK(t, err, "GetClientDefaultScopes")
		},
		"GetClientOptionalScopes": func() {
			_, err := svc.GetClientOptionalScopes(ctx, "", "c1")
			requireOK(t, err, "GetClientOptionalScopes")
		},
		"GetClientScopeMappings": func() {
			_, err := svc.GetClientScopeMappings(ctx, "", "c1")
			requireOK(t, err, "GetClientScopeMappings")
		},
		"GetClientSessions": func() { _, err := svc.GetClientSessions(ctx, "", "c1", 0, 10); requireOK(t, err, "GetClientSessions") },
		"GetClientOfflineSessions": func() {
			_, err := svc.GetClientOfflineSessions(ctx, "", "c1", 0, 10)
			requireOK(t, err, "GetClientOfflineSessions")
		},
		"GetDefaultDefaultClientScopes": func() {
			_, err := svc.GetDefaultDefaultClientScopes(ctx, "")
			requireOK(t, err, "GetDefaultDefaultClientScopes")
		},
		"GetDefaultOptionalClientScopes": func() {
			_, err := svc.GetDefaultOptionalClientScopes(ctx, "")
			requireOK(t, err, "GetDefaultOptionalClientScopes")
		},
	} {
		t.Run(name, func(*testing.T) { call() })
	}
}

func TestExtendedRoleAndGroupServiceMethods(t *testing.T) {
	ctx := context.Background()
	svc := newExtendedFixtureService()

	for name, call := range map[string]func(){
		"GetRoleByID":     func() { _, err := svc.GetRoleByID(ctx, "", "r1"); requireOK(t, err, "GetRoleByID") },
		"GetGroupsInRole": func() { _, err := svc.GetGroupsInRole(ctx, "", "viewer"); requireOK(t, err, "GetGroupsInRole") },
		"GetGroupsInClientRole": func() {
			_, err := svc.GetGroupsInClientRole(ctx, "", "c1", "viewer")
			requireOK(t, err, "GetGroupsInClientRole")
		},
		"GetGroupByPath":   func() { _, err := svc.GetGroupByPath(ctx, "", "/eng/devs"); requireOK(t, err, "GetGroupByPath") },
		"ListChildGroups":  func() { _, err := svc.ListChildGroups(ctx, "", "g1", 0, 10, ""); requireOK(t, err, "ListChildGroups") },
		"GetDefaultGroups": func() { _, err := svc.GetDefaultGroups(ctx, ""); requireOK(t, err, "GetDefaultGroups") },
	} {
		t.Run(name, func(*testing.T) { call() })
	}
}

func TestExtendedRealmsAndAuthServiceMethods(t *testing.T) {
	ctx := context.Background()
	svc := newExtendedFixtureService()

	ks, err := svc.GetRealmKeys(ctx, "")
	requireOK(t, err, "GetRealmKeys")
	requireCount(t, len(ks.Keys), 1, "GetRealmKeys")
	certs, err := svc.GetRealmCerts(ctx, "")
	requireOK(t, err, "GetRealmCerts")
	requireCount(t, len(certs), 1, "GetRealmCerts")
	si, err := svc.GetServerInfo(ctx)
	requireOK(t, err, "GetServerInfo")
	if si.Version != "26.1.0" {
		t.Fatalf("GetServerInfo version = %q", si.Version)
	}

	for name, call := range map[string]func(){
		"GetRealmIssuer":        func() { _, err := svc.GetRealmIssuer(ctx, ""); requireOK(t, err, "GetRealmIssuer") },
		"GetUserProfileConfig":  func() { _, err := svc.GetUserProfileConfig(ctx, ""); requireOK(t, err, "GetUserProfileConfig") },
		"GetAuthenticationFlow": func() { _, err := svc.GetAuthenticationFlow(ctx, "", "f1"); requireOK(t, err, "GetAuthenticationFlow") },
		"GetAuthenticatorConfig": func() {
			_, err := svc.GetAuthenticatorConfig(ctx, "", "ac1")
			requireOK(t, err, "GetAuthenticatorConfig")
		},
		"GetRequiredAction": func() {
			_, err := svc.GetRequiredAction(ctx, "", "CONFIGURE_TOTP")
			requireOK(t, err, "GetRequiredAction")
		},
		"ListUnregisteredRequiredActions": func() {
			_, err := svc.ListUnregisteredRequiredActions(ctx, "")
			requireOK(t, err, "ListUnregisteredRequiredActions")
		},
		"ListIdentityProviderMappers": func() {
			_, err := svc.ListIdentityProviderMappers(ctx, "", "okta")
			requireOK(t, err, "ListIdentityProviderMappers")
		},
		"GetIdentityProviderMapper": func() {
			_, err := svc.GetIdentityProviderMapper(ctx, "", "okta", "im1")
			requireOK(t, err, "GetIdentityProviderMapper")
		},
	} {
		t.Run(name, func(*testing.T) { call() })
	}
}

func TestExtendedOrgAndComponentServiceMethods(t *testing.T) {
	ctx := context.Background()
	svc := newExtendedFixtureService()

	for name, call := range map[string]func(){
		"GetOrganization":    func() { _, err := svc.GetOrganization(ctx, "", "o1"); requireOK(t, err, "GetOrganization") },
		"CountOrganizations": func() { _, err := svc.CountOrganizations(ctx, "", ""); requireOK(t, err, "CountOrganizations") },
		"CountOrganizationMembers": func() {
			_, err := svc.CountOrganizationMembers(ctx, "", "o1")
			requireOK(t, err, "CountOrganizationMembers")
		},
		"GetOrganizationMember": func() {
			_, err := svc.GetOrganizationMember(ctx, "", "o1", "u1")
			requireOK(t, err, "GetOrganizationMember")
		},
		"GetUserOrganizations": func() { _, err := svc.GetUserOrganizations(ctx, "", "u1"); requireOK(t, err, "GetUserOrganizations") },
		"ListOrganizationIdentityProviders": func() {
			_, err := svc.ListOrganizationIdentityProviders(ctx, "", "o1")
			requireOK(t, err, "ListOrganizationIdentityProviders")
		},
		"ListOrganizationInvitations": func() {
			_, err := svc.ListOrganizationInvitations(ctx, "", "o1", 0, 10, "")
			requireOK(t, err, "ListOrganizationInvitations")
		},
		"ListOrganizationGroups": func() {
			_, err := svc.ListOrganizationGroups(ctx, "", "o1", 0, 10, "")
			requireOK(t, err, "ListOrganizationGroups")
		},
		"ListComponents": func() { _, err := svc.ListComponents(ctx, "", ComponentFilter{}); requireOK(t, err, "ListComponents") },
		"GetComponent":   func() { _, err := svc.GetComponent(ctx, "", "cmp1"); requireOK(t, err, "GetComponent") },
	} {
		t.Run(name, func(*testing.T) { call() })
	}
}

func TestExtendedAuthzServiceMethods(t *testing.T) {
	ctx := context.Background()
	svc := newExtendedFixtureService()

	for name, call := range map[string]func(){
		"GetResourceServer": func() { _, err := svc.GetResourceServer(ctx, "", "c1"); requireOK(t, err, "GetResourceServer") },
		"ListAuthzResources": func() {
			_, err := svc.ListAuthzResources(ctx, "", "c1", 0, 10, &AuthzResourceFilter{})
			requireOK(t, err, "ListAuthzResources")
		},
		"GetAuthzResource": func() { _, err := svc.GetAuthzResource(ctx, "", "c1", "res1"); requireOK(t, err, "GetAuthzResource") },
		"ListAuthzScopes":  func() { _, err := svc.ListAuthzScopes(ctx, "", "c1", 0, 10, ""); requireOK(t, err, "ListAuthzScopes") },
		"GetAuthzScope":    func() { _, err := svc.GetAuthzScope(ctx, "", "c1", "as1"); requireOK(t, err, "GetAuthzScope") },
		"ListAuthzPolicies": func() {
			_, err := svc.ListAuthzPolicies(ctx, "", "c1", 0, 10, AuthzPolicyFilter{})
			requireOK(t, err, "ListAuthzPolicies")
		},
		"GetAuthzPolicy": func() { _, err := svc.GetAuthzPolicy(ctx, "", "c1", "pol1"); requireOK(t, err, "GetAuthzPolicy") },
		"ListAuthzPermissions": func() {
			_, err := svc.ListAuthzPermissions(ctx, "", "c1", 0, 10, AuthzPermissionFilter{})
			requireOK(t, err, "ListAuthzPermissions")
		},
		"GetAuthzPermission": func() {
			_, err := svc.GetAuthzPermission(ctx, "", "c1", "perm1")
			requireOK(t, err, "GetAuthzPermission")
		},
		"GetPolicyAssociatedPolicies": func() {
			_, err := svc.GetPolicyAssociatedPolicies(ctx, "", "c1", "pol1")
			requireOK(t, err, "GetPolicyAssociatedPolicies")
		},
		"GetPolicyResources": func() {
			_, err := svc.GetPolicyResources(ctx, "", "c1", "pol1")
			requireOK(t, err, "GetPolicyResources")
		},
		"GetPolicyScopes": func() { _, err := svc.GetPolicyScopes(ctx, "", "c1", "pol1"); requireOK(t, err, "GetPolicyScopes") },
	} {
		t.Run(name, func(*testing.T) { call() })
	}
}
