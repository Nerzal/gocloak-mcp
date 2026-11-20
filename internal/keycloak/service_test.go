package keycloak

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Nerzal/gocloak/v14"
)

type stubClient struct {
	Client
	err          error
	users        []*gocloak.User
	user         *gocloak.User
	userCount    int
	sessions     []*gocloak.UserSessionRepresentation
	groups       []*gocloak.Group
	group        *gocloak.Group
	groupCount   int
	mappings     *gocloak.MappingsRepresentation
	clients      []*gocloak.Client
	client       *gocloak.Client
	roles        []*gocloak.Role
	role         *gocloak.Role
	scopes       []*gocloak.ClientScope
	scope        *gocloak.ClientScope
	realms       []*gocloak.RealmRepresentation
	realm        *gocloak.RealmRepresentation
	events       []*gocloak.EventRepresentation
	adminEvents  []*gocloak.AdminEventRepresentation
	flows        []*gocloak.AuthenticationFlowRepresentation
	executions   []*gocloak.ModifyAuthenticationExecutionRepresentation
	actions      []*gocloak.RequiredActionProviderRepresentation
	idps         []*gocloak.IdentityProviderRepresentation
	idp          *gocloak.IdentityProviderRepresentation
	orgs         []*gocloak.OrganizationRepresentation
	orgMembers   []*gocloak.MemberRepresentation
	lastRealm    string
	usersParams  gocloak.GetUsersParams
	getUsersHook func(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error)
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

func TestUsersOperationsAndBriefRepresentation(t *testing.T) {
	ctx := context.Background()
	u := &gocloak.User{ID: strP("u1"), Username: strP("alice"), Email: strP("a@ex.test"), Enabled: boolP(true)}
	client := &stubClient{
		users:     []*gocloak.User{nil, u},
		user:      u,
		userCount: 42,
		sessions:  []*gocloak.UserSessionRepresentation{nil, {ID: strP("s1"), Username: strP("alice"), Clients: map[string]string{"c1": "app"}}},
		groups:    []*gocloak.Group{nil, {ID: strP("g1"), Name: strP("devs"), Path: strP("/devs")}},
		mappings:  &gocloak.MappingsRepresentation{RealmMappings: []gocloak.Role{{ID: strP("r1"), Name: strP("admin")}}, ClientMappings: map[string]*gocloak.ClientMappingsRepresentation{"app": {Mappings: []gocloak.Role{{ID: strP("r2"), Name: strP("reader")}}}}},
	}
	svc := NewService(client, &stubTokenProvider{}, "primary", []string{"primary", "secondary"})

	users, err := svc.ListUsers(ctx, "secondary", 0, 10, UserFilter{Search: "ali", Exact: true})
	if err != nil || len(users) != 1 || client.lastRealm != "secondary" || client.usersParams.BriefRepresentation == nil || !*client.usersParams.BriefRepresentation {
		t.Fatalf("ListUsers() = %+v, %v (realm=%s)", users, err, client.lastRealm)
	}
	if got, err := svc.GetUser(ctx, "", "u1"); err != nil || got.Username != "alice" {
		t.Fatalf("GetUser() = %+v, %v", got, err)
	}
	if count, err := svc.CountUsers(ctx, "", UserFilter{Search: "ali"}); err != nil || count != 42 {
		t.Fatalf("CountUsers() = %d, %v", count, err)
	}
	if sessions, err := svc.GetUserSessions(ctx, "", "u1"); err != nil || len(sessions) != 1 || sessions[0].Clients["c1"] != "app" {
		t.Fatalf("GetUserSessions() = %+v, %v", sessions, err)
	}
	if groups, err := svc.GetUserGroups(ctx, "", "u1", 0, 10); err != nil || len(groups) != 1 || groups[0].Path != "/devs" {
		t.Fatalf("GetUserGroups() = %+v, %v", groups, err)
	}
	if roles, err := svc.GetUserRoles(ctx, "", "u1"); err != nil || len(roles.RealmRoles) != 1 || len(roles.ClientRoles["app"]) != 1 {
		t.Fatalf("GetUserRoles() = %+v, %v", roles, err)
	}
}

func newDomainFixtureService() Service {
	cl := &gocloak.Client{ID: strP("c1"), ClientID: strP("web"), Name: strP("Web"), Enabled: boolP(true), Secret: strP("never-expose")}
	role := &gocloak.Role{ID: strP("r1"), Name: strP("viewer")}
	scope := &gocloak.ClientScope{ID: strP("sc1"), Name: strP("email"), Protocol: strP("openid-connect")}
	grp := &gocloak.Group{ID: strP("g1"), Name: strP("ops"), Path: strP("/ops")}
	usr := &gocloak.User{ID: strP("u1"), Username: strP("svc-web"), Enabled: boolP(true)}
	mt := gocloak.MembershipTypeManaged
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
		events:      []*gocloak.EventRepresentation{nil, {Time: 100, Type: strP("LOGIN"), ClientID: strP("web")}},
		adminEvents: []*gocloak.AdminEventRepresentation{nil, {Time: 200, OperationType: strP("CREATE"), ResourceType: strP("USER"), AuthDetails: &gocloak.AdminEventAuthDetailsRepresentation{ClientID: strP("admin-cli")}, Representation: strP("secret-payload")}},
		flows:       []*gocloak.AuthenticationFlowRepresentation{nil, {ID: strP("f1"), Alias: strP("browser"), TopLevel: boolP(true)}},
		executions:  []*gocloak.ModifyAuthenticationExecutionRepresentation{nil, {ID: strP("e1"), DisplayName: strP("Cookie"), Requirement: strP("ALTERNATIVE")}},
		actions:     []*gocloak.RequiredActionProviderRepresentation{nil, {Alias: strP("UPDATE_PASSWORD"), Enabled: boolP(true)}},
		idps:        []*gocloak.IdentityProviderRepresentation{nil, {Alias: strP("google"), ProviderID: strP("oidc"), Enabled: boolP(true), Config: map[string]string{"clientSecret": "top-secret"}}},
		idp:         &gocloak.IdentityProviderRepresentation{Alias: strP("google"), ProviderID: strP("oidc"), Enabled: boolP(true)},
		orgs:        []*gocloak.OrganizationRepresentation{nil, {ID: strP("o1"), Name: strP("Acme"), Domains: []gocloak.OrganizationDomainRepresentation{{Name: strP("acme.test")}}}},
		orgMembers:  []*gocloak.MemberRepresentation{nil, {User: gocloak.User{ID: strP("u1"), Username: strP("alice")}, MembershipType: &mt}},
	}, &stubTokenProvider{}, "primary", []string{"primary"})
}

func TestClientsAndScopesOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	if list, err := svc.ListClients(ctx, "", 0, 10, ClientFilter{ClientID: "web"}); err != nil || len(list) != 1 {
		t.Fatalf("ListClients() = %+v, %v", list, err)
	}
	if got, err := svc.GetClient(ctx, "", "c1"); err != nil || got.ClientID != "web" {
		t.Fatalf("GetClient() = %+v, %v", got, err)
	}
	if sa, err := svc.GetClientServiceAccount(ctx, "", "c1"); err != nil || sa.Username != "svc-web" {
		t.Fatalf("GetClientServiceAccount() = %+v, %v", sa, err)
	}
	if roles, err := svc.ListClientRoles(ctx, "", "c1", 0, 10, ""); err != nil || len(roles) != 1 {
		t.Fatalf("ListClientRoles() = %+v, %v", roles, err)
	}
	if scopes, err := svc.ListClientScopes(ctx, ""); err != nil || len(scopes) != 1 {
		t.Fatalf("ListClientScopes() = %+v, %v", scopes, err)
	}
	if sc, err := svc.GetClientScope(ctx, "", "sc1"); err != nil || sc.Name != "email" {
		t.Fatalf("GetClientScope() = %+v, %v", sc, err)
	}
}

func TestRolesOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	if roles, err := svc.ListRealmRoles(ctx, "", 0, 10, ""); err != nil || len(roles) != 1 {
		t.Fatalf("ListRealmRoles() = %+v, %v", roles, err)
	}
	if r, err := svc.GetRealmRole(ctx, "", "viewer"); err != nil || r.Name != "viewer" {
		t.Fatalf("GetRealmRole() = %+v, %v", r, err)
	}
	if users, err := svc.GetUsersInRole(ctx, "", "viewer", 0, 10); err != nil || len(users) != 1 {
		t.Fatalf("GetUsersInRole() = %+v, %v", users, err)
	}
	if users, err := svc.GetUsersInClientRole(ctx, "", "c1", "viewer", 0, 10); err != nil || len(users) != 1 {
		t.Fatalf("GetUsersInClientRole() = %+v, %v", users, err)
	}
}

func TestGroupsOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	if groups, err := svc.ListGroups(ctx, "", 0, 10, "ops"); err != nil || len(groups) != 1 {
		t.Fatalf("ListGroups() = %+v, %v", groups, err)
	}
	if n, err := svc.CountGroups(ctx, "", "ops"); err != nil || n != 7 {
		t.Fatalf("CountGroups() = %d, %v", n, err)
	}
	if g, err := svc.GetGroup(ctx, "", "g1"); err != nil || g.Name != "ops" {
		t.Fatalf("GetGroup() = %+v, %v", g, err)
	}
	if members, err := svc.GetGroupMembers(ctx, "", "g1", 0, 10); err != nil || len(members) != 1 {
		t.Fatalf("GetGroupMembers() = %+v, %v", members, err)
	}
	if roles, err := svc.GetGroupRoles(ctx, "", "g1"); err != nil || len(roles.RealmRoles) != 0 {
		t.Fatalf("GetGroupRoles() = %+v, %v", roles, err)
	}
}

func TestRealmsAndEventsOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	realms, err := svc.ListRealms(ctx)
	if err != nil || len(realms) != 1 || realms[0].Name != "primary" {
		t.Fatalf("ListRealms() = %+v, %v", realms, err)
	}
	if info, err := svc.GetRealmInfo(ctx, ""); err != nil || info.Name != "primary" {
		t.Fatalf("GetRealmInfo() = %+v, %v", info, err)
	}
	if ev, err := svc.ListEvents(ctx, "", 0, 10, EventFilter{Type: []string{"LOGIN"}}); err != nil || len(ev) != 1 {
		t.Fatalf("ListEvents() = %+v, %v", ev, err)
	}
	if aev, err := svc.ListAdminEvents(ctx, "", 0, 10, AdminEventFilter{OperationTypes: []string{"CREATE"}}); err != nil || len(aev) != 1 || aev[0].AuthClientID != "admin-cli" {
		t.Fatalf("ListAdminEvents() = %+v, %v", aev, err)
	}
}

func TestAuthFlowsIdPAndOrganizationsOperations(t *testing.T) {
	ctx := context.Background()
	svc := newDomainFixtureService()
	if flows, err := svc.ListAuthenticationFlows(ctx, ""); err != nil || len(flows) != 1 {
		t.Fatalf("ListAuthenticationFlows() = %+v, %v", flows, err)
	}
	if execs, err := svc.GetFlowExecutions(ctx, "", "browser"); err != nil || len(execs) != 1 {
		t.Fatalf("GetFlowExecutions() = %+v, %v", execs, err)
	}
	if acts, err := svc.ListRequiredActions(ctx, ""); err != nil || len(acts) != 1 {
		t.Fatalf("ListRequiredActions() = %+v, %v", acts, err)
	}
	if idps, err := svc.ListIdentityProviders(ctx, ""); err != nil || len(idps) != 1 {
		t.Fatalf("ListIdentityProviders() = %+v, %v", idps, err)
	}
	if idp, err := svc.GetIdentityProvider(ctx, "", "google"); err != nil || idp.Alias != "google" {
		t.Fatalf("GetIdentityProvider() = %+v, %v", idp, err)
	}
	if orgs, err := svc.ListOrganizations(ctx, "", 0, 10, ""); err != nil || len(orgs) != 1 || len(orgs[0].Domains) != 1 {
		t.Fatalf("ListOrganizations() = %+v, %v", orgs, err)
	}
	if members, err := svc.GetOrganizationMembers(ctx, "", "o1", 0, 10, ""); err != nil || len(members) != 1 || members[0].MembershipType != "MANAGED" {
		t.Fatalf("GetOrganizationMembers() = %+v, %v", members, err)
	}
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
