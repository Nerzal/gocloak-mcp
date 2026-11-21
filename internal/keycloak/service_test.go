package keycloak

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Nerzal/gocloak/v15"
)

type stubClient struct {
	Client
	err              error
	users            []*gocloak.User
	user             *gocloak.User
	userCount        int
	sessions         []*gocloak.UserSessionRepresentation
	groups           []*gocloak.Group
	group            *gocloak.Group
	groupCount       int
	mappings         *gocloak.MappingsRepresentation
	clients          []*gocloak.Client
	client           *gocloak.Client
	roles            []*gocloak.Role
	role             *gocloak.Role
	scopes           []*gocloak.ClientScope
	scope            *gocloak.ClientScope
	realms           []*gocloak.RealmRepresentation
	realm            *gocloak.RealmRepresentation
	events           []*gocloak.EventRepresentation
	adminEvents      []*gocloak.AdminEventRepresentation
	flows            []*gocloak.AuthenticationFlowRepresentation
	executions       []*gocloak.ModifyAuthenticationExecutionRepresentation
	actions          []*gocloak.RequiredActionProviderRepresentation
	idps             []*gocloak.IdentityProviderRepresentation
	idp              *gocloak.IdentityProviderRepresentation
	orgs             []*gocloak.OrganizationRepresentation
	org              *gocloak.OrganizationRepresentation
	orgCount         int64
	orgMembers       []*gocloak.MemberRepresentation
	orgMember        *gocloak.MemberRepresentation
	orgMemberCount   int
	invitations      []*gocloak.OrganizationInvitationRepresentation
	creds            []*gocloak.CredentialRepresentation
	fedIDs           []*gocloak.FederatedIdentityRepresentation
	bruteForce       *gocloak.BruteForceStatus
	scopeMappers     []*gocloak.ProtocolMappers
	scopeMapper      *gocloak.ProtocolMappers
	keyStore         *gocloak.KeyStoreConfig
	certs            *gocloak.CertResponse
	issuer           *gocloak.IssuerResponse
	userProfile      *gocloak.UserProfileConfig
	serverInfo       *gocloak.ServerInfoRepresentation
	flow             *gocloak.AuthenticationFlowRepresentation
	authConfig       *gocloak.AuthenticatorConfigRepresentation
	action           *gocloak.RequiredActionProviderRepresentation
	unregActions     []*gocloak.UnregisteredRequiredActionProviderRepresentation
	idpMappers       []*gocloak.IdentityProviderMapper
	idpMapper        *gocloak.IdentityProviderMapper
	components       []*gocloak.Component
	component        *gocloak.Component
	resourceServer   *gocloak.ResourceServerRepresentation
	authzResources   []*gocloak.ResourceRepresentation
	authzResource    *gocloak.ResourceRepresentation
	authzScopes      []*gocloak.ScopeRepresentation
	authzScope       *gocloak.ScopeRepresentation
	authzPolicies    []*gocloak.PolicyRepresentation
	authzPolicy      *gocloak.PolicyRepresentation
	authzPermissions []*gocloak.PermissionRepresentation
	authzPermission  *gocloak.PermissionRepresentation
	policyResources  []*gocloak.PolicyResourceRepresentation
	policyScopes     []*gocloak.PolicyScopeRepresentation
	lastRealm        string
	usersParams      gocloak.GetUsersParams
	getUsersHook     func(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error)
}

//nolint:gocritic // GoCloak's interface requires GetUsersParams by value.
func (c *stubClient) GetUsers(ctx context.Context, tok, realm string, p gocloak.GetUsersParams) ([]*gocloak.User, error) {
	c.lastRealm, c.usersParams = realm, p
	if c.getUsersHook != nil {
		return c.getUsersHook(ctx, tok, realm, p)
	}
	return c.users, c.err
}

func (c *stubClient) GetUserByID(_ context.Context, _, realm, _ string) (*gocloak.User, error) {
	c.lastRealm = realm
	return c.user, c.err
}

//nolint:gocritic // GoCloak's interface requires GetUsersParams by value.
func (c *stubClient) GetUserCount(_ context.Context, _, realm string, _ gocloak.GetUsersParams) (int, error) {
	c.lastRealm = realm
	return c.userCount, c.err
}

func (c *stubClient) GetUserSessions(_ context.Context, _, realm, _ string) ([]*gocloak.UserSessionRepresentation, error) {
	c.lastRealm = realm
	return c.sessions, c.err
}

func (c *stubClient) GetUserGroups(_ context.Context, _, realm, _ string, _ gocloak.GetGroupsParams) ([]*gocloak.Group, error) {
	c.lastRealm = realm
	return c.groups, c.err
}

func (c *stubClient) GetRoleMappingByUserID(_ context.Context, _, realm, _ string) (*gocloak.MappingsRepresentation, error) {
	c.lastRealm = realm
	return c.mappings, c.err
}

func (c *stubClient) GetClients(_ context.Context, _, realm string, _ gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	c.lastRealm = realm
	return c.clients, c.err
}

func (c *stubClient) GetClient(_ context.Context, _, realm, _ string) (*gocloak.Client, error) {
	c.lastRealm = realm
	return c.client, c.err
}

func (c *stubClient) GetClientServiceAccount(_ context.Context, _, realm, _ string) (*gocloak.User, error) {
	c.lastRealm = realm
	return c.user, c.err
}

func (c *stubClient) GetClientRoles(_ context.Context, _, realm, _ string, _ gocloak.GetRoleParams) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetClientScopes(_ context.Context, _, realm string) ([]*gocloak.ClientScope, error) {
	c.lastRealm = realm
	return c.scopes, c.err
}

func (c *stubClient) GetClientScope(_ context.Context, _, realm, _ string) (*gocloak.ClientScope, error) {
	c.lastRealm = realm
	return c.scope, c.err
}

func (c *stubClient) GetRealmRoles(_ context.Context, _, realm string, _ gocloak.GetRoleParams) ([]*gocloak.Role, error) {
	c.lastRealm = realm
	return c.roles, c.err
}

func (c *stubClient) GetRealmRole(_ context.Context, _, realm, _ string) (*gocloak.Role, error) {
	c.lastRealm = realm
	return c.role, c.err
}

func (c *stubClient) GetUsersByRoleName(_ context.Context, _, realm, _ string, _ gocloak.GetUsersByRoleParams) ([]*gocloak.User, error) {
	c.lastRealm = realm
	return c.users, c.err
}

func (c *stubClient) GetUsersByClientRoleName(_ context.Context, _, realm, _, _ string, _ gocloak.GetUsersByRoleParams) ([]*gocloak.User, error) {
	c.lastRealm = realm
	return c.users, c.err
}

func (c *stubClient) GetGroups(_ context.Context, _, realm string, _ gocloak.GetGroupsParams) ([]*gocloak.Group, error) {
	c.lastRealm = realm
	return c.groups, c.err
}

func (c *stubClient) GetGroupsCount(_ context.Context, _, realm string, _ gocloak.GetGroupsParams) (int, error) {
	c.lastRealm = realm
	return c.groupCount, c.err
}

func (c *stubClient) GetGroup(_ context.Context, _, realm, _ string) (*gocloak.Group, error) {
	c.lastRealm = realm
	return c.group, c.err
}

func (c *stubClient) GetGroupMembers(_ context.Context, _, realm, _ string, _ gocloak.GetGroupsParams) ([]*gocloak.User, error) {
	c.lastRealm = realm
	return c.users, c.err
}

func (c *stubClient) GetRoleMappingByGroupID(_ context.Context, _, realm, _ string) (*gocloak.MappingsRepresentation, error) {
	c.lastRealm = realm
	return c.mappings, c.err
}

func (c *stubClient) GetRealms(_ context.Context, _ string) ([]*gocloak.RealmRepresentation, error) {
	return c.realms, c.err
}

func (c *stubClient) GetRealm(_ context.Context, _, realm string) (*gocloak.RealmRepresentation, error) {
	c.lastRealm = realm
	return c.realm, c.err
}

//nolint:gocritic // GoCloak's interface requires GetEventsParams by value.
func (c *stubClient) GetEvents(_ context.Context, _, realm string, _ gocloak.GetEventsParams) ([]*gocloak.EventRepresentation, error) {
	c.lastRealm = realm
	return c.events, c.err
}

//nolint:gocritic // GoCloak's interface requires GetAdminEventsParams by value.
func (c *stubClient) GetAdminEvents(_ context.Context, _, realm string, _ gocloak.GetAdminEventsParams) ([]*gocloak.AdminEventRepresentation, error) {
	c.lastRealm = realm
	return c.adminEvents, c.err
}

func (c *stubClient) GetAuthenticationFlows(_ context.Context, _, realm string) ([]*gocloak.AuthenticationFlowRepresentation, error) {
	c.lastRealm = realm
	return c.flows, c.err
}

func (c *stubClient) GetAuthenticationExecutions(_ context.Context, _, realm, _ string) ([]*gocloak.ModifyAuthenticationExecutionRepresentation, error) {
	c.lastRealm = realm
	return c.executions, c.err
}

func (c *stubClient) GetRequiredActions(_ context.Context, _, realm string) ([]*gocloak.RequiredActionProviderRepresentation, error) {
	c.lastRealm = realm
	return c.actions, c.err
}

func (c *stubClient) GetIdentityProviders(_ context.Context, _, realm string) ([]*gocloak.IdentityProviderRepresentation, error) {
	c.lastRealm = realm
	return c.idps, c.err
}

func (c *stubClient) GetIdentityProvider(_ context.Context, _, realm, _ string) (*gocloak.IdentityProviderRepresentation, error) {
	c.lastRealm = realm
	return c.idp, c.err
}

func (c *stubClient) GetOrganizations(_ context.Context, _, realm string, _ gocloak.GetOrganizationsParams) ([]*gocloak.OrganizationRepresentation, error) {
	c.lastRealm = realm
	return c.orgs, c.err
}

func (c *stubClient) GetOrganizationMembers(_ context.Context, _, realm, _ string, _ gocloak.GetMembersParams) ([]*gocloak.MemberRepresentation, error) {
	c.lastRealm = realm
	return c.orgMembers, c.err
}

type stubTokenProvider struct {
	tokens      []string
	err         error
	invalidated int
	index       int
}

func (p *stubTokenProvider) Token(context.Context) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	if p.index < len(p.tokens) {
		tok := p.tokens[p.index]
		p.index++
		return tok, nil
	}
	return "access", nil
}

func (p *stubTokenProvider) Invalidate() { p.invalidated++ }

func strP(s string) *string { return &s }
func boolP(b bool) *bool    { return &b }

func requireOK(t *testing.T, err error, name string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s error = %v", name, err)
	}
}

func requireCount(t *testing.T, got, want int, name string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s count = %d, want %d", name, got, want)
	}
}

func TestUsersOperationsAndBriefRepresentation(t *testing.T) {
	ctx := context.Background()
	u := &gocloak.User{ID: strP("u1"), Username: strP("alice"), Email: strP("a@ex.test"), Enabled: boolP(true)}
	client := &stubClient{
		users:     []*gocloak.User{nil, u},
		user:      u,
		userCount: 42,
		sessions:  []*gocloak.UserSessionRepresentation{nil, {ID: "s1", Username: "alice", Clients: map[string]string{"c1": "app"}}},
		groups:    []*gocloak.Group{nil, {ID: strP("g1"), Name: strP("devs"), Path: strP("/devs")}},
		mappings:  &gocloak.MappingsRepresentation{RealmMappings: []gocloak.Role{{ID: strP("r1"), Name: strP("admin")}}, ClientMappings: map[string]gocloak.ClientMappingsRepresentation{"app": {Mappings: []gocloak.Role{{ID: strP("r2"), Name: strP("reader")}}}}},
	}
	svc := NewService(client, &stubTokenProvider{}, "primary", []string{"primary", "secondary"})

	users, err := svc.ListUsers(ctx, "secondary", 0, 10, UserFilter{Search: "ali", Exact: true})
	requireOK(t, err, "ListUsers")
	requireCount(t, len(users), 1, "ListUsers")
	if client.lastRealm != "secondary" || client.usersParams.BriefRepresentation == nil || !*client.usersParams.BriefRepresentation {
		t.Fatalf("unexpected realm=%s or brief=%v", client.lastRealm, client.usersParams.BriefRepresentation)
	}
	got, err := svc.GetUser(ctx, "", "u1")
	requireOK(t, err, "GetUser")
	if got.Username != "alice" {
		t.Fatalf("GetUser() = %+v", got)
	}
	count, err := svc.CountUsers(ctx, "", UserFilter{Search: "ali"})
	requireOK(t, err, "CountUsers")
	requireCount(t, count, 42, "CountUsers")

	sessions, err := svc.GetUserSessions(ctx, "", "u1")
	requireOK(t, err, "GetUserSessions")
	requireCount(t, len(sessions), 1, "GetUserSessions")

	groups, err := svc.GetUserGroups(ctx, "", "u1", 0, 10)
	requireOK(t, err, "GetUserGroups")
	requireCount(t, len(groups), 1, "GetUserGroups")

	roles, err := svc.GetUserRoles(ctx, "", "u1")
	requireOK(t, err, "GetUserRoles")
	requireCount(t, len(roles.RealmRoles), 1, "GetUserRoles.RealmRoles")
	requireCount(t, len(roles.ClientRoles["app"]), 1, "GetUserRoles.ClientRoles")
}

func newDomainFixtureService() Service {
	cl := &gocloak.Client{ID: strP("c1"), ClientID: strP("web"), Name: strP("Web"), Enabled: boolP(true), Secret: strP("never-expose")}
	role := &gocloak.Role{ID: strP("r1"), Name: strP("viewer")}
	scope := &gocloak.ClientScope{ID: strP("sc1"), Name: strP("email"), Protocol: strP("openid-connect")}
	grp := &gocloak.Group{ID: strP("g1"), Name: strP("ops"), Path: strP("/ops")}
	usr := &gocloak.User{ID: strP("u1"), Username: strP("svc-web"), Enabled: boolP(true)}
	return NewService(&stubClient{
		clients: []*gocloak.Client{nil, cl}, client: cl, user: usr, users: []*gocloak.User{usr},
		roles: []*gocloak.Role{nil, role}, role: role, scopes: []*gocloak.ClientScope{nil, scope}, scope: scope,
		groups: []*gocloak.Group{nil, grp}, group: grp, groupCount: 7, mappings: &gocloak.MappingsRepresentation{},
		realms: []*gocloak.RealmRepresentation{
			nil,
			{ID: strP("1"), Realm: strP("primary"), Enabled: boolP(true)},
			{ID: strP("2"), Realm: strP("forbidden-realm"), Enabled: boolP(true)},
		},
		realm:       &gocloak.RealmRepresentation{ID: strP("1"), Realm: strP("primary"), Enabled: boolP(true)},
		events:      []*gocloak.EventRepresentation{nil, {Time: 100, Type: "LOGIN", ClientID: "web"}},
		adminEvents: []*gocloak.AdminEventRepresentation{nil, {Time: 200, OperationType: "CREATE", ResourceType: "USER", AuthDetails: gocloak.AdminEventAuthDetailsRepresentation{ClientID: "admin-cli"}, Representation: "secret-payload"}},
		flows:       []*gocloak.AuthenticationFlowRepresentation{nil, {ID: strP("f1"), Alias: strP("browser"), TopLevel: boolP(true)}},
		executions:  []*gocloak.ModifyAuthenticationExecutionRepresentation{nil, {ID: strP("e1"), DisplayName: strP("Cookie"), Requirement: strP("ALTERNATIVE")}},
		actions:     []*gocloak.RequiredActionProviderRepresentation{nil, {Alias: strP("UPDATE_PASSWORD"), Enabled: boolP(true)}},
		idps:        []*gocloak.IdentityProviderRepresentation{nil, {Alias: strP("google"), ProviderID: strP("oidc"), Enabled: boolP(true), Config: map[string]string{"clientSecret": "top-secret"}}},
		idp:         &gocloak.IdentityProviderRepresentation{Alias: strP("google"), ProviderID: strP("oidc"), Enabled: boolP(true)},
		orgs:        []*gocloak.OrganizationRepresentation{nil, {ID: strP("o1"), Name: strP("Acme"), Domains: []gocloak.OrganizationDomainRepresentation{{Name: strP("acme.test")}}}},
		orgMembers:  []*gocloak.MemberRepresentation{nil, {User: gocloak.User{ID: strP("u1"), Username: strP("alice")}, MembershipType: gocloak.MembershipTypeManaged}},
	}, &stubTokenProvider{}, "primary", []string{"primary"})
}

func TestClientsAndScopesOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	list, err := svc.ListClients(ctx, "", 0, 10, ClientFilter{ClientID: "web"})
	requireOK(t, err, "ListClients")
	requireCount(t, len(list), 1, "ListClients")

	got, err := svc.GetClient(ctx, "", "c1")
	requireOK(t, err, "GetClient")
	if got.ClientID != "web" {
		t.Fatalf("GetClient() = %+v", got)
	}
	sa, err := svc.GetClientServiceAccount(ctx, "", "c1")
	requireOK(t, err, "GetClientServiceAccount")
	if sa.Username != "svc-web" {
		t.Fatalf("GetClientServiceAccount() = %+v", sa)
	}
	roles, err := svc.ListClientRoles(ctx, "", "c1", 0, 10, "")
	requireOK(t, err, "ListClientRoles")
	requireCount(t, len(roles), 1, "ListClientRoles")

	scopes, err := svc.ListClientScopes(ctx, "")
	requireOK(t, err, "ListClientScopes")
	requireCount(t, len(scopes), 1, "ListClientScopes")

	sc, err := svc.GetClientScope(ctx, "", "sc1")
	requireOK(t, err, "GetClientScope")
	if sc.Name != "email" {
		t.Fatalf("GetClientScope() = %+v", sc)
	}
}

func TestRolesOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	roles, err := svc.ListRealmRoles(ctx, "", 0, 10, "")
	requireOK(t, err, "ListRealmRoles")
	requireCount(t, len(roles), 1, "ListRealmRoles")

	r, err := svc.GetRealmRole(ctx, "", "viewer")
	requireOK(t, err, "GetRealmRole")
	if r.Name != "viewer" {
		t.Fatalf("GetRealmRole() = %+v", r)
	}
	users, err := svc.GetUsersInRole(ctx, "", "viewer", 0, 10)
	requireOK(t, err, "GetUsersInRole")
	requireCount(t, len(users), 1, "GetUsersInRole")

	clientUsers, err := svc.GetUsersInClientRole(ctx, "", "c1", "viewer", 0, 10)
	requireOK(t, err, "GetUsersInClientRole")
	requireCount(t, len(clientUsers), 1, "GetUsersInClientRole")
}

func TestGroupsOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	groups, err := svc.ListGroups(ctx, "", 0, 10, "ops")
	requireOK(t, err, "ListGroups")
	requireCount(t, len(groups), 1, "ListGroups")

	n, err := svc.CountGroups(ctx, "", "ops")
	requireOK(t, err, "CountGroups")
	requireCount(t, n, 7, "CountGroups")

	g, err := svc.GetGroup(ctx, "", "g1")
	requireOK(t, err, "GetGroup")
	if g.Name != "ops" {
		t.Fatalf("GetGroup() = %+v", g)
	}
	members, err := svc.GetGroupMembers(ctx, "", "g1", 0, 10)
	requireOK(t, err, "GetGroupMembers")
	requireCount(t, len(members), 1, "GetGroupMembers")

	roles, err := svc.GetGroupRoles(ctx, "", "g1")
	requireOK(t, err, "GetGroupRoles")
	requireCount(t, len(roles.RealmRoles), 0, "GetGroupRoles")
}

func TestRealmsAndEventsOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	realms, err := svc.ListRealms(ctx)
	requireOK(t, err, "ListRealms")
	requireCount(t, len(realms), 1, "ListRealms")

	info, err := svc.GetRealmInfo(ctx, "")
	requireOK(t, err, "GetRealmInfo")
	if info.Name != "primary" {
		t.Fatalf("GetRealmInfo() = %+v", info)
	}
	ev, err := svc.ListEvents(ctx, "", 0, 10, &EventFilter{Type: []string{"LOGIN"}})
	requireOK(t, err, "ListEvents")
	requireCount(t, len(ev), 1, "ListEvents")

	aev, err := svc.ListAdminEvents(ctx, "", 0, 10, &AdminEventFilter{OperationTypes: []string{"CREATE"}})
	requireOK(t, err, "ListAdminEvents")
	requireCount(t, len(aev), 1, "ListAdminEvents")
}

func TestAuthFlowsIdPAndOrganizationsOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	flows, err := svc.ListAuthenticationFlows(ctx, "")
	requireOK(t, err, "ListAuthenticationFlows")
	requireCount(t, len(flows), 1, "ListAuthenticationFlows")

	execs, err := svc.GetFlowExecutions(ctx, "", "browser")
	requireOK(t, err, "GetFlowExecutions")
	requireCount(t, len(execs), 1, "GetFlowExecutions")

	acts, err := svc.ListRequiredActions(ctx, "")
	requireOK(t, err, "ListRequiredActions")
	requireCount(t, len(acts), 1, "ListRequiredActions")

	idps, err := svc.ListIdentityProviders(ctx, "")
	requireOK(t, err, "ListIdentityProviders")
	requireCount(t, len(idps), 1, "ListIdentityProviders")

	idp, err := svc.GetIdentityProvider(ctx, "", "google")
	requireOK(t, err, "GetIdentityProvider")
	if idp.Alias != "google" {
		t.Fatalf("GetIdentityProvider() = %+v", idp)
	}
	orgs, err := svc.ListOrganizations(ctx, "", 0, 10, "")
	requireOK(t, err, "ListOrganizations")
	requireCount(t, len(orgs), 1, "ListOrganizations")

	members, err := svc.GetOrganizationMembers(ctx, "", "o1", 0, 10, "")
	requireOK(t, err, "GetOrganizationMembers")
	requireCount(t, len(members), 1, "GetOrganizationMembers")
}

func TestSecurityValidationAndUnauthorizedRetry(t *testing.T) {
	ctx := context.Background()
	tokens := &stubTokenProvider{tokens: []string{"stale", "fresh"}}
	client := &stubClient{
		getUsersHook: func(_ context.Context, tok, _ string, _ gocloak.GetUsersParams) ([]*gocloak.User, error) {
			if tok == "stale" {
				return nil, &gocloak.APIError{Code: http.StatusUnauthorized, Message: "expired"}
			}
			return []*gocloak.User{{ID: strP("u1")}}, nil
		},
	}
	svc := NewService(client, tokens, "primary", []string{"primary"})

	if _, err := svc.ListUsers(ctx, "not-allowed", 0, 10, UserFilter{}); !errors.Is(err, errRealmNotAllowed) {
		t.Fatalf("disallowed realm error = %v, want errRealmNotAllowed", err)
	}
	if _, err := svc.GetUser(ctx, "", "../admin"); !errors.Is(err, errInvalidID) {
		t.Fatalf("traversal userID error = %v, want errInvalidID", err)
	}
	if _, err := svc.ListUsers(ctx, "", -1, 10, UserFilter{}); !errors.Is(err, errInvalidPage) {
		t.Fatalf("invalid page error = %v, want errInvalidPage", err)
	}
	users, err := svc.ListUsers(ctx, "", 0, 10, UserFilter{})
	if err != nil || len(users) != 1 || tokens.invalidated != 1 {
		t.Fatalf("401 retry failed: users=%+v err=%v invalidated=%d", users, err, tokens.invalidated)
	}

	failSvc := NewService(&stubClient{err: errors.New("raw bearer secret")}, &stubTokenProvider{}, "primary", nil)
	if _, err := failSvc.GetRealmInfo(ctx, ""); err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("GetRealmInfo() error = %v, want sanitized error", err)
	}
}
