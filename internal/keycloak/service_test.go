package keycloak

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak/v14"
)

type serviceClient struct {
	users       []*gocloak.User
	clients     []*gocloak.Client
	realm       *gocloak.RealmRepresentation
	err         error
	usersParams gocloak.GetUsersParams
	getUsersFn  func(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error)
}

func (*serviceClient) GetToken(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
	return &gocloak.JWT{AccessToken: "token", ExpiresIn: 60}, nil
}

func (c *serviceClient) GetUsers(ctx context.Context, token, realm string, params gocloak.GetUsersParams) ([]*gocloak.User, error) {
	c.usersParams = params
	if c.getUsersFn != nil {
		return c.getUsersFn(ctx, token, realm, params)
	}
	return c.users, c.err
}

func (c *serviceClient) GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	return c.clients, c.err
}

func (c *serviceClient) GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error) {
	return c.realm, c.err
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

func (p *stubTokenProvider) Invalidate() {
	p.invalidated++
}

func TestServiceMapsOnlySafeUserFieldsAndUsesBriefRepresentation(t *testing.T) {
	username, email, id, marker := "alice", "alice@example.test", "user-id", "private-marker"
	enabled := true
	client := &serviceClient{
		users: []*gocloak.User{
			nil,
			{ID: &id, Username: &username, Email: &email, Enabled: &enabled, FirstName: &marker},
		},
	}
	svc := NewService(client, &stubTokenProvider{}, "realm")

	users, err := svc.ListUsers(context.Background(), 0, 10)
	if err != nil || len(users) != 1 {
		t.Fatalf("ListUsers() = %v, %v", users, err)
	}
	if client.usersParams.BriefRepresentation == nil || !*client.usersParams.BriefRepresentation {
		t.Fatalf("BriefRepresentation = %v, want true", client.usersParams.BriefRepresentation)
	}
	if users[0].Username != username || users[0].Email != email || !users[0].Enabled || strings.Contains(users[0].Username, marker) {
		t.Fatalf("ListUsers() = %+v", users)
	}
}

func TestServiceListClientsMapsSafeFields(t *testing.T) {
	id, clientID, name, secret := "c-1", "web-app", "Web App", "do-not-expose"
	enabled, public := true, false
	svc := NewService(&serviceClient{
		clients: []*gocloak.Client{
			nil,
			{ID: &id, ClientID: &clientID, Name: &name, Enabled: &enabled, PublicClient: &public, Secret: &secret},
		},
	}, &stubTokenProvider{}, "realm")

	clients, err := svc.ListClients(context.Background(), 0, 10)
	if err != nil || len(clients) != 1 {
		t.Fatalf("ListClients() = %v, %v", clients, err)
	}
	if clients[0].ID != id || clients[0].ClientID != clientID || clients[0].Name != name || !clients[0].Enabled || clients[0].Public {
		t.Fatalf("ListClients() = %+v", clients)
	}
}

func TestServiceGetRealmInfoMapsSafeFieldsAndHandlesNil(t *testing.T) {
	id, realmName, display := "r-1", "example", "Example Realm"
	enabled := true
	svc := NewService(&serviceClient{
		realm: &gocloak.RealmRepresentation{ID: &id, Realm: &realmName, DisplayName: &display, Enabled: &enabled},
	}, &stubTokenProvider{}, "example")

	info, err := svc.GetRealmInfo(context.Background())
	if err != nil || info.ID != id || info.Name != realmName || info.DisplayName != display || !info.Enabled {
		t.Fatalf("GetRealmInfo() = %+v, %v", info, err)
	}

	nilSvc := NewService(&serviceClient{realm: nil}, &stubTokenProvider{}, "example")
	if _, err := nilSvc.GetRealmInfo(context.Background()); err == nil {
		t.Fatal("GetRealmInfo() with nil realm error = nil")
	}
}

func TestServiceRetriesOnceOnUnauthorized(t *testing.T) {
	id := "u-1"
	tokens := &stubTokenProvider{tokens: []string{"stale-token", "fresh-token"}}
	client := &serviceClient{
		getUsersFn: func(_ context.Context, token, _ string, _ gocloak.GetUsersParams) ([]*gocloak.User, error) {
			if token == "stale-token" {
				return nil, &gocloak.APIError{Code: http.StatusUnauthorized, Message: "expired"}
			}
			return []*gocloak.User{{ID: &id}}, nil
		},
	}
	svc := NewService(client, tokens, "realm")

	users, err := svc.ListUsers(context.Background(), 0, 10)
	if err != nil || len(users) != 1 || users[0].ID != id {
		t.Fatalf("ListUsers() = %+v, %v", users, err)
	}
	if tokens.invalidated != 1 {
		t.Fatalf("Invalidate() calls = %d, want 1", tokens.invalidated)
	}
}

func TestServiceSanitizesUpstreamAndTokenErrors(t *testing.T) {
	svc := NewService(&serviceClient{err: errors.New("raw body includes bearer-secret")}, &stubTokenProvider{}, "realm")
	if _, err := svc.ListClients(context.Background(), 0, 10); err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("ListClients() error = %v, want sanitized error", err)
	}
	tokenFailSvc := NewService(&serviceClient{}, &stubTokenProvider{err: errors.New("secret-leak")}, "realm")
	if _, err := tokenFailSvc.GetRealmInfo(context.Background()); err == nil || err.Error() != "keycloak request failed" {
		t.Fatalf("GetRealmInfo() error = %v, want sanitized error", err)
	}
}

func TestServiceRejectsInvalidPagination(t *testing.T) {
	svc := NewService(&serviceClient{}, &stubTokenProvider{}, "realm")
	for _, page := range [][2]int{{-1, 10}, {0, 0}, {0, 101}} {
		if _, err := svc.ListUsers(context.Background(), page[0], page[1]); err == nil {
			t.Errorf("ListUsers(%d, %d) error = nil", page[0], page[1])
		}
		if _, err := svc.ListClients(context.Background(), page[0], page[1]); err == nil {
			t.Errorf("ListClients(%d, %d) error = nil", page[0], page[1])
		}
	}
}
