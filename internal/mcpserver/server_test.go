package mcpserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type stubService struct {
	err error
}

func (s *stubService) ListUsers(context.Context, string, int, int, keycloak.UserFilter) ([]keycloak.User, error) {
	return []keycloak.User{{ID: "u1", Username: "alice", Enabled: true}}, s.err
}

func (s *stubService) GetUser(context.Context, string, string) (keycloak.User, error) {
	return keycloak.User{ID: "u1", Username: "alice"}, s.err
}

func (s *stubService) CountUsers(context.Context, string, keycloak.UserFilter) (int, error) {
	return 1, s.err
}

func (s *stubService) GetUserSessions(context.Context, string, string) ([]keycloak.UserSession, error) {
	return []keycloak.UserSession{{ID: "s1"}}, s.err
}

func (s *stubService) GetUserGroups(context.Context, string, string, int, int) ([]keycloak.GroupInfo, error) {
	return []keycloak.GroupInfo{{ID: "g1", Name: "devs"}}, s.err
}

func (s *stubService) GetUserRoles(context.Context, string, string) (keycloak.RoleMappings, error) {
	return keycloak.RoleMappings{RealmRoles: []keycloak.RoleInfo{{ID: "r1", Name: "viewer"}}}, s.err
}

func (s *stubService) ListClients(context.Context, string, int, int, keycloak.ClientFilter) ([]keycloak.ClientInfo, error) {
	return []keycloak.ClientInfo{{ID: "c1", ClientID: "web"}}, s.err
}

func (s *stubService) GetClient(context.Context, string, string) (keycloak.ClientInfo, error) {
	return keycloak.ClientInfo{ID: "c1", ClientID: "web"}, s.err
}

func (s *stubService) GetClientServiceAccount(context.Context, string, string) (keycloak.User, error) {
	return keycloak.User{ID: "sa1", Username: "svc-web"}, s.err
}

func (s *stubService) ListClientRoles(context.Context, string, string, int, int, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "cr1", Name: "read"}}, s.err
}

func (s *stubService) ListClientScopes(context.Context, string) ([]keycloak.ClientScopeInfo, error) {
	return []keycloak.ClientScopeInfo{{ID: "sc1", Name: "email"}}, s.err
}

func (s *stubService) GetClientScope(context.Context, string, string) (keycloak.ClientScopeInfo, error) {
	return keycloak.ClientScopeInfo{ID: "sc1", Name: "email"}, s.err
}

func (s *stubService) ListRealmRoles(context.Context, string, int, int, string) ([]keycloak.RoleInfo, error) {
	return []keycloak.RoleInfo{{ID: "r1", Name: "viewer"}}, s.err
}

func (s *stubService) GetRealmRole(context.Context, string, string) (keycloak.RoleInfo, error) {
	return keycloak.RoleInfo{ID: "r1", Name: "viewer"}, s.err
}

func (s *stubService) GetUsersInRole(context.Context, string, string, int, int) ([]keycloak.User, error) {
	return []keycloak.User{{ID: "u1"}}, s.err
}

func (s *stubService) GetUsersInClientRole(context.Context, string, string, string, int, int) ([]keycloak.User, error) {
	return []keycloak.User{{ID: "u1"}}, s.err
}

func (s *stubService) ListGroups(context.Context, string, int, int, string) ([]keycloak.GroupInfo, error) {
	return []keycloak.GroupInfo{{ID: "g1", Name: "devs"}}, s.err
}

func (s *stubService) CountGroups(context.Context, string, string) (int, error) {
	return 1, s.err
}

func (s *stubService) GetGroup(context.Context, string, string) (keycloak.GroupInfo, error) {
	return keycloak.GroupInfo{ID: "g1", Name: "devs"}, s.err
}

func (s *stubService) GetGroupMembers(context.Context, string, string, int, int) ([]keycloak.User, error) {
	return []keycloak.User{{ID: "u1"}}, s.err
}

func (s *stubService) GetGroupRoles(context.Context, string, string) (keycloak.RoleMappings, error) {
	return keycloak.RoleMappings{RealmRoles: []keycloak.RoleInfo{}}, s.err
}

func (s *stubService) ListRealms(context.Context) ([]keycloak.RealmInfo, error) {
	return []keycloak.RealmInfo{{ID: "1", Name: "example", Enabled: true}}, s.err
}

func (s *stubService) GetRealmInfo(context.Context, string) (keycloak.RealmInfo, error) {
	return keycloak.RealmInfo{ID: "1", Name: "example", Enabled: true}, s.err
}

func (s *stubService) ListEvents(context.Context, string, int, int, *keycloak.EventFilter) ([]keycloak.EventInfo, error) {
	return []keycloak.EventInfo{{Type: "LOGIN"}}, s.err
}

func (s *stubService) ListAdminEvents(context.Context, string, int, int, *keycloak.AdminEventFilter) ([]keycloak.AdminEventInfo, error) {
	return []keycloak.AdminEventInfo{{OperationType: "CREATE"}}, s.err
}

func (s *stubService) ListAuthenticationFlows(context.Context, string) ([]keycloak.AuthFlowInfo, error) {
	return []keycloak.AuthFlowInfo{{ID: "f1", Alias: "browser"}}, s.err
}

func (s *stubService) GetFlowExecutions(context.Context, string, string) ([]keycloak.FlowExecutionInfo, error) {
	return []keycloak.FlowExecutionInfo{{ID: "e1", Alias: "cookie"}}, s.err
}

func (s *stubService) ListRequiredActions(context.Context, string) ([]keycloak.RequiredActionInfo, error) {
	return []keycloak.RequiredActionInfo{{Alias: "UPDATE_PASSWORD"}}, s.err
}

func (s *stubService) ListIdentityProviders(context.Context, string) ([]keycloak.IdentityProviderInfo, error) {
	return []keycloak.IdentityProviderInfo{{Alias: "google"}}, s.err
}

func (s *stubService) GetIdentityProvider(context.Context, string, string) (keycloak.IdentityProviderInfo, error) {
	return keycloak.IdentityProviderInfo{Alias: "google"}, s.err
}

func (s *stubService) ListOrganizations(context.Context, string, int, int, string) ([]keycloak.OrganizationInfo, error) {
	return []keycloak.OrganizationInfo{{ID: "o1", Name: "Acme"}}, s.err
}

func (s *stubService) GetOrganizationMembers(context.Context, string, string, int, int, string) ([]keycloak.OrganizationMember, error) {
	return []keycloak.OrganizationMember{{User: keycloak.User{ID: "u1"}}}, s.err
}

func intPtr(v int) *int { return &v }

func connectInMemory(t *testing.T, svc Service, logger *slog.Logger) (session *mcp.ClientSession, cleanup func()) {
	t.Helper()
	ctx := context.Background()
	server := New(svc, 0, logger)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
	session, err = client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		t.Fatalf("client.Connect() error = %v", err)
	}
	return session, func() {
		_ = session.Close()
		_ = serverSession.Close()
	}
}

const expectedReadOnlyToolCount = 98

func TestAll98ReadOnlyToolsRegisteredAndCallable(t *testing.T) {
	ctx := context.Background()
	session, cleanup := connectInMemory(t, &stubService{}, nil)
	defer cleanup()

	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != expectedReadOnlyToolCount {
		t.Fatalf("ListTools() count = %d, err = %v; want %d", len(listed.Tools), err, expectedReadOnlyToolCount)
	}
	for _, tool := range listed.Tools {
		assertReadOnlyToolCallable(ctx, t, session, tool)
	}
}

func assertReadOnlyToolCallable(ctx context.Context, t *testing.T, session *mcp.ClientSession, tool *mcp.Tool) {
	t.Helper()
	if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint ||
		tool.Annotations.DestructiveHint == nil || *tool.Annotations.DestructiveHint {
		t.Errorf("tool %q does not declare read-only non-destructive annotations", tool.Name)
	}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool.Name, Arguments: sampleArgs(tool.Name)})
	if err != nil || res.IsError {
		t.Errorf("CallTool(%s) failed: err=%v isError=%v", tool.Name, err, res != nil && res.IsError)
	}
}

var toolSampleArgs = map[string]map[string]any{
	"get_user":                             {"userId": "u1"},
	"get_user_sessions":                    {"userId": "u1"},
	"get_user_offline_sessions":            {"userId": "u1", "clientUuid": "c1"},
	"get_user_groups":                      {"userId": "u1"},
	"get_user_roles":                       {"userId": "u1"},
	"get_user_credentials":                 {"userId": "u1"},
	"get_user_federated_identities":        {"userId": "u1"},
	"get_user_brute_force_status":          {"userId": "u1"},
	"get_user_composite_realm_roles":       {"userId": "u1"},
	"get_user_composite_client_roles":      {"userId": "u1", "clientUuid": "c1"},
	"get_user_available_realm_roles":       {"userId": "u1"},
	"get_user_available_client_roles":      {"userId": "u1", "clientUuid": "c1"},
	"get_client":                           {"clientUuid": "c1"},
	"get_client_service_account":           {"clientUuid": "c1"},
	"list_client_roles":                    {"clientUuid": "c1"},
	"get_client_role":                      {"clientUuid": "c1", "roleName": "read"},
	"get_client_protocol_mappers":          {"clientUuid": "c1"},
	"get_client_default_scopes":            {"clientUuid": "c1"},
	"get_client_optional_scopes":           {"clientUuid": "c1"},
	"get_client_scope_mappings":            {"clientUuid": "c1"},
	"get_client_sessions":                  {"clientUuid": "c1"},
	"get_client_offline_sessions":          {"clientUuid": "c1"},
	"get_client_scope":                     {"scopeId": "sc1"},
	"list_client_scope_protocol_mappers":   {"scopeId": "sc1"},
	"get_client_scope_protocol_mapper":     {"scopeId": "sc1", "mapperId": "pm1"},
	"get_client_scope_realm_roles":         {"scopeId": "sc1"},
	"get_client_scope_client_roles":        {"scopeId": "sc1", "clientUuid": "c1"},
	"get_realm_role":                       {"roleName": "viewer"},
	"get_role_by_id":                       {"roleId": "r1"},
	"get_realm_role_composites":            {"roleName": "viewer"},
	"get_role_composites_by_id":            {"roleId": "r1"},
	"get_users_in_role":                    {"roleName": "viewer"},
	"get_users_in_client_role":             {"clientUuid": "c1", "roleName": "read"},
	"get_groups_in_role":                   {"roleName": "viewer"},
	"get_groups_in_client_role":            {"clientUuid": "c1", "roleName": "read"},
	"get_group":                            {"groupId": "g1"},
	"get_group_by_path":                    {"groupPath": "/eng/devs"},
	"list_child_groups":                    {"groupId": "g1"},
	"get_group_members":                    {"groupId": "g1"},
	"get_group_roles":                      {"groupId": "g1"},
	"get_group_composite_realm_roles":      {"groupId": "g1"},
	"get_group_composite_client_roles":     {"groupId": "g1", "clientUuid": "c1"},
	"get_group_available_realm_roles":      {"groupId": "g1"},
	"get_group_available_client_roles":     {"groupId": "g1", "clientUuid": "c1"},
	"get_authentication_flow":              {"flowId": "f1"},
	"get_flow_executions":                  {"flowAlias": "browser"},
	"get_authenticator_config":             {"configId": "ac1"},
	"get_required_action":                  {"alias": "CONFIGURE_TOTP"},
	"get_identity_provider":                {"alias": "google"},
	"list_identity_provider_mappers":       {"alias": "google"},
	"get_identity_provider_mapper":         {"alias": "google", "mapperId": "im1"},
	"get_organization":                     {"organizationId": "o1"},
	"get_organization_members":             {"organizationId": "o1"},
	"count_organization_members":           {"organizationId": "o1"},
	"get_organization_member":              {"organizationId": "o1", "userId": "u1"},
	"get_user_organizations":               {"userId": "u1"},
	"list_organization_identity_providers": {"organizationId": "o1"},
	"list_organization_invitations":        {"organizationId": "o1"},
	"list_organization_groups":             {"organizationId": "o1"},
	"get_component":                        {"componentId": "cmp1"},
	"get_resource_server":                  {"clientUuid": "c1"},
	"list_authz_resources":                 {"clientUuid": "c1"},
	"get_authz_resource":                   {"clientUuid": "c1", "resourceId": "res1"},
	"list_authz_scopes":                    {"clientUuid": "c1"},
	"get_authz_scope":                      {"clientUuid": "c1", "scopeId": "as1"},
	"list_authz_policies":                  {"clientUuid": "c1"},
	"get_authz_policy":                     {"clientUuid": "c1", "policyId": "pol1"},
	"list_authz_permissions":               {"clientUuid": "c1"},
	"get_authz_permission":                 {"clientUuid": "c1", "permissionId": "perm1"},
	"get_policy_associated_policies":       {"clientUuid": "c1", "policyId": "pol1"},
	"get_policy_resources":                 {"clientUuid": "c1", "policyId": "pol1"},
	"get_policy_scopes":                    {"clientUuid": "c1", "policyId": "pol1"},
}

func sampleArgs(toolName string) map[string]any {
	if args, ok := toolSampleArgs[toolName]; ok {
		return args
	}
	return map[string]any{}
}

func TestValidatePageRejectsInvalidAndExplicitZeroMax(t *testing.T) {
	first, maxSize, err := validatePage(pageInput{})
	if err != nil || first != 0 || maxSize != defaultPageSize {
		t.Fatalf("validatePage({}) = (%d, %d, %v)", first, maxSize, err)
	}
	for _, input := range []pageInput{
		{First: -1, Max: intPtr(10)},
		{First: 0, Max: intPtr(0)},
		{First: 0, Max: intPtr(-5)},
		{First: 0, Max: intPtr(101)},
	} {
		if _, _, err := validatePage(input); err == nil {
			t.Errorf("validatePage(%+v) error = nil", input)
		}
	}
}

func TestExecuteToolSanitizesErrorAndLogsSafely(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	deps := toolDeps{timeout: time.Second, logger: logger}
	_, _, err := executeTool(context.Background(), deps, "list_users", func(context.Context) (usersOutput, error) {
		return usersOutput{}, errors.New("raw-secret-body")
	})
	if err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("executeTool() error = %v", err)
	}
	if logs := buf.String(); strings.Contains(logs, "raw-secret-body") || !strings.Contains(logs, `"tool":"list_users"`) {
		t.Fatalf("unexpected log output: %s", logs)
	}
}
