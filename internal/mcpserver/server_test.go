package mcpserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Nerzal/gocloak-mcp/internal/keycloak"
)

type testService struct {
	usersErr error
	users    []keycloak.User
	first    int
	max      int
}

func (s *testService) ListUsers(_ context.Context, first, pageSize int) ([]keycloak.User, error) {
	s.first, s.max = first, pageSize
	return s.users, s.usersErr
}

func (*testService) ListClients(context.Context, int, int) ([]keycloak.ClientInfo, error) {
	return []keycloak.ClientInfo{}, nil
}

func (*testService) GetRealmInfo(context.Context) (keycloak.RealmInfo, error) {
	return keycloak.RealmInfo{}, nil
}

func TestListUsersDefaultsPageSize(t *testing.T) {
	service := &testService{users: []keycloak.User{{ID: "id"}}}
	_, output, err := listUsers(context.Background(), service, time.Second, pageInput{})
	if err != nil || len(output) != 1 {
		t.Fatalf("listUsers() = %v, %v", output, err)
	}
	if service.first != 0 || service.max != 50 {
		t.Fatalf("page = (%d, %d), want (0, 50)", service.first, service.max)
	}
}

func TestListUsersRejectsInvalidPage(t *testing.T) {
	service := &testService{}
	for _, input := range []pageInput{{First: -1, Max: 10}, {First: 0, Max: 101}} {
		if _, _, err := listUsers(context.Background(), service, time.Second, input); err == nil {
			t.Errorf("listUsers(%+v) error = nil", input)
		}
	}
}

func TestToolErrorsAreSanitized(t *testing.T) {
	service := &testService{usersErr: errors.New("raw-keycloak-response")}
	_, _, err := listUsers(context.Background(), service, time.Second, pageInput{Max: 10})
	if err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("listUsers() error = %v, want sanitized error", err)
	}
}
