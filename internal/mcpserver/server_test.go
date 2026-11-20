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

type testService struct {
	usersErr   error
	clientsErr error
	realmErr   error
	users      []keycloak.User
	clients    []keycloak.ClientInfo
	realm      keycloak.RealmInfo
	first      int
	max        int
}

func (s *testService) ListUsers(_ context.Context, first, pageSize int) ([]keycloak.User, error) {
	s.first, s.max = first, pageSize
	return s.users, s.usersErr
}

func (s *testService) ListClients(_ context.Context, first, pageSize int) ([]keycloak.ClientInfo, error) {
	s.first, s.max = first, pageSize
	return s.clients, s.clientsErr
}

func (s *testService) GetRealmInfo(context.Context) (keycloak.RealmInfo, error) {
	return s.realm, s.realmErr
}

func intPtr(v int) *int { return &v }

func TestListUsersDefaultsPageSizeAndWrapsOutput(t *testing.T) {
	service := &testService{users: []keycloak.User{{ID: "id"}}}
	_, output, err := listUsers(context.Background(), service, time.Second, nil, pageInput{})
	if err != nil || len(output.Users) != 1 || output.Users[0].ID != "id" {
		t.Fatalf("listUsers() = %+v, %v", output, err)
	}
	if service.first != 0 || service.max != defaultPageSize {
		t.Fatalf("page = (%d, %d), want (0, %d)", service.first, service.max, defaultPageSize)
	}
}

func TestListClientsAndGetRealmInfoSuccess(t *testing.T) {
	service := &testService{
		clients: []keycloak.ClientInfo{{ID: "c1", ClientID: "app"}},
		realm:   keycloak.RealmInfo{ID: "r1", Name: "example", Enabled: true},
	}
	_, clientsOut, err := listClients(context.Background(), service, time.Second, nil, pageInput{First: 5, Max: intPtr(20)})
	if err != nil || len(clientsOut.Clients) != 1 || service.first != 5 || service.max != 20 {
		t.Fatalf("listClients() = %+v, %v", clientsOut, err)
	}
	_, realmOut, err := getRealmInfo(context.Background(), service, time.Second, nil)
	if err != nil || realmOut.Name != "example" || !realmOut.Enabled {
		t.Fatalf("getRealmInfo() = %+v, %v", realmOut, err)
	}
}

func TestPaginationRejectsInvalidAndExplicitZeroMax(t *testing.T) {
	service := &testService{}
	invalid := []pageInput{
		{First: -1, Max: intPtr(10)},
		{First: 0, Max: intPtr(0)},
		{First: 0, Max: intPtr(-5)},
		{First: 0, Max: intPtr(101)},
	}
	for _, input := range invalid {
		if _, _, err := listUsers(context.Background(), service, time.Second, nil, input); err == nil {
			t.Errorf("listUsers(%+v) error = nil", input)
		}
		if _, _, err := listClients(context.Background(), service, time.Second, nil, input); err == nil {
			t.Errorf("listClients(%+v) error = nil", input)
		}
	}
}

func TestToolErrorsAreSanitizedAndLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	service := &testService{
		usersErr:   errors.New("raw-keycloak-response"),
		clientsErr: errors.New("raw-clients-error"),
		realmErr:   errors.New("raw-realm-error"),
	}
	if _, _, err := listUsers(context.Background(), service, time.Second, logger, pageInput{Max: intPtr(10)}); err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("listUsers() error = %v", err)
	}
	if _, _, err := listClients(context.Background(), service, time.Second, logger, pageInput{Max: intPtr(10)}); err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("listClients() error = %v", err)
	}
	if _, _, err := getRealmInfo(context.Background(), service, time.Second, logger); err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("getRealmInfo() error = %v", err)
	}
	if logs := buf.String(); strings.Contains(logs, "raw-") || !strings.Contains(logs, `"tool":"list_users"`) {
		t.Fatalf("unexpected log output: %s", logs)
	}
}

func TestNewRegistersReadOnlyToolsOverInMemoryTransport(t *testing.T) {
	ctx := context.Background()
	service := &testService{
		users:   []keycloak.User{{ID: "u1", Username: "alice", Enabled: true}},
		clients: []keycloak.ClientInfo{{ID: "c1", ClientID: "web", Enabled: true}},
		realm:   keycloak.RealmInfo{ID: "r1", Name: "example", Enabled: true},
	}
	server := New(service, 0, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect() error = %v", err)
	}
	defer func() { _ = serverSession.Close() }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer func() { _ = session.Close() }()

	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatalf("ListTools() = %v, %v", tools, err)
	}
	for _, tool := range tools.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("tool %q missing ReadOnlyHint", tool.Name)
		}
	}
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_users"}); err != nil {
		t.Fatalf("CallTool(list_users) error = %v", err)
	}
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_clients"}); err != nil {
		t.Fatalf("CallTool(list_clients) error = %v", err)
	}
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "get_realm_info"}); err != nil {
		t.Fatalf("CallTool(get_realm_info) error = %v", err)
	}
}
