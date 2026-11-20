package keycloak

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak/v14"
)

type serviceClient struct {
	users   []*gocloak.User
	clients []*gocloak.Client
	realm   *gocloak.RealmRepresentation
	err     error
}

func (*serviceClient) GetToken(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
	return &gocloak.JWT{AccessToken: "token", ExpiresIn: 60}, nil
}

func (c *serviceClient) GetUsers(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error) {
	return c.users, c.err
}

func (c *serviceClient) GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	return c.clients, c.err
}

func (c *serviceClient) GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error) {
	return c.realm, c.err
}

type staticToken string

func (token staticToken) Token(context.Context) (string, error) {
	return string(token), nil
}

func TestServiceMapsOnlySafeUserFields(t *testing.T) {
	username, email, id, marker := "alice", "alice@example.test", "user-id", "private-marker"
	service := NewService(&serviceClient{
		users: []*gocloak.User{
			nil,
			{ID: &id, Username: &username, Email: &email, FirstName: &marker},
		},
	}, staticToken("access"), "realm")

	users, err := service.ListUsers(context.Background(), 0, 10)
	if err != nil || len(users) != 1 {
		t.Fatalf("ListUsers() = %v, %v", users, err)
	}
	if users[0].Username != username || users[0].Email != email || strings.Contains(users[0].Username, marker) {
		t.Fatalf("ListUsers() = %+v", users)
	}
}

func TestServiceSanitizesUpstreamErrors(t *testing.T) {
	service := NewService(&serviceClient{err: errors.New("raw body includes bearer-secret")}, staticToken("access"), "realm")
	_, err := service.ListClients(context.Background(), 0, 10)
	if err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("ListClients() error = %v, want sanitized error", err)
	}
}

func TestServiceRejectsInvalidPagination(t *testing.T) {
	service := NewService(&serviceClient{}, staticToken("access"), "realm")
	for _, page := range [][2]int{{-1, 10}, {0, 0}, {0, 101}} {
		if _, err := service.ListUsers(context.Background(), page[0], page[1]); err == nil {
			t.Errorf("ListUsers(%d, %d) error = nil", page[0], page[1])
		}
	}
}
