package keycloak

import (
	"context"
	"errors"

	"github.com/Nerzal/gocloak/v14"
)

// Service exposes the read-only operations used by MCP handlers.
type Service interface {
	ListUsers(context.Context, int, int) ([]User, error)
	ListClients(context.Context, int, int) ([]ClientInfo, error)
	GetRealmInfo(context.Context) (RealmInfo, error)
}

type service struct {
	client Client
	tokens TokenProvider
	realm  string
}

// NewService constructs a Keycloak service from its API and token dependencies.
func NewService(client Client, tokens TokenProvider, realm string) Service {
	return &service{client: client, tokens: tokens, realm: realm}
}

func (s *service) ListUsers(ctx context.Context, first, pageSize int) ([]User, error) {
	if err := validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return nil, errors.New("keycloak request failed")
	}
	users, err := s.client.GetUsers(ctx, token, s.realm, gocloak.GetUsersParams{
		First: &first,
		Max:   &pageSize,
	})
	if err != nil {
		return nil, errors.New("keycloak request failed")
	}
	return mapUsers(users), nil
}

func (s *service) ListClients(ctx context.Context, first, pageSize int) ([]ClientInfo, error) {
	if err := validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return nil, errors.New("keycloak request failed")
	}
	clients, err := s.client.GetClients(ctx, token, s.realm, gocloak.GetClientsParams{
		First: &first,
		Max:   &pageSize,
	})
	if err != nil {
		return nil, errors.New("keycloak request failed")
	}
	return mapClients(clients), nil
}

func (s *service) GetRealmInfo(ctx context.Context) (RealmInfo, error) {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return RealmInfo{}, errors.New("keycloak request failed")
	}
	realm, err := s.client.GetRealm(ctx, token, s.realm)
	if err != nil || realm == nil {
		return RealmInfo{}, errors.New("keycloak request failed")
	}
	return mapRealm(realm), nil
}

func validatePagination(first, pageSize int) error {
	if first < 0 || pageSize < 1 || pageSize > 100 {
		return errors.New("invalid pagination parameters")
	}
	return nil
}

func mapUsers(users []*gocloak.User) []User {
	result := make([]User, 0, len(users))
	for _, user := range users {
		if user != nil {
			result = append(result, mapUser(user))
		}
	}
	return result
}

func mapUser(user *gocloak.User) User {
	result := User{}
	if user.ID != nil {
		result.ID = *user.ID
	}
	if user.Username != nil {
		result.Username = *user.Username
	}
	if user.Email != nil {
		result.Email = *user.Email
	}
	if user.Enabled != nil {
		result.Enabled = *user.Enabled
	}
	return result
}

func mapClients(clients []*gocloak.Client) []ClientInfo {
	result := make([]ClientInfo, 0, len(clients))
	for _, client := range clients {
		if client != nil {
			result = append(result, mapClient(client))
		}
	}
	return result
}

func mapClient(client *gocloak.Client) ClientInfo {
	result := ClientInfo{}
	if client.ID != nil {
		result.ID = *client.ID
	}
	if client.ClientID != nil {
		result.ClientID = *client.ClientID
	}
	if client.Name != nil {
		result.Name = *client.Name
	}
	if client.Enabled != nil {
		result.Enabled = *client.Enabled
	}
	if client.PublicClient != nil {
		result.Public = *client.PublicClient
	}
	return result
}

func mapRealm(realm *gocloak.RealmRepresentation) RealmInfo {
	result := RealmInfo{}
	if realm.ID != nil {
		result.ID = *realm.ID
	}
	if realm.Realm != nil {
		result.Name = *realm.Realm
	}
	if realm.DisplayName != nil {
		result.DisplayName = *realm.DisplayName
	}
	if realm.Enabled != nil {
		result.Enabled = *realm.Enabled
	}
	return result
}
