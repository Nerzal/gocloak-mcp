package keycloak

import (
	"context"
	"errors"

	"github.com/Nerzal/gocloak/v14"
)

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

func NewService(client Client, tokens TokenProvider, realm string) Service {
	return &service{client: client, tokens: tokens, realm: realm}
}

func (s *service) ListUsers(ctx context.Context, first, max int) ([]User, error) {
	if first < 0 || max < 1 || max > 100 {
		return nil, errors.New("invalid pagination parameters")
	}
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return nil, errors.New("Keycloak request failed")
	}
	users, err := s.client.GetUsers(ctx, token, s.realm, gocloak.GetUsersParams{
		First: &first,
		Max:   &max,
	})
	if err != nil {
		return nil, errors.New("Keycloak request failed")
	}
	return mapUsers(users), nil
}

func (s *service) ListClients(ctx context.Context, first, max int) ([]ClientInfo, error) {
	if first < 0 || max < 1 || max > 100 {
		return nil, errors.New("invalid pagination parameters")
	}
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return nil, errors.New("Keycloak request failed")
	}
	clients, err := s.client.GetClients(ctx, token, s.realm, gocloak.GetClientsParams{
		First: &first,
		Max:   &max,
	})
	if err != nil {
		return nil, errors.New("Keycloak request failed")
	}
	return mapClients(clients), nil
}

func (s *service) GetRealmInfo(ctx context.Context) (RealmInfo, error) {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return RealmInfo{}, errors.New("Keycloak request failed")
	}
	realm, err := s.client.GetRealm(ctx, token, s.realm)
	if err != nil || realm == nil {
		return RealmInfo{}, errors.New("Keycloak request failed")
	}
	return mapRealm(realm), nil
}

func mapUsers(users []*gocloak.User) []User {
	result := make([]User, 0, len(users))
	for _, user := range users {
		if user == nil {
			continue
		}
		result = append(result, User{
			ID:       stringValue(user.ID),
			Username: stringValue(user.Username),
			Email:    stringValue(user.Email),
			Enabled:  boolValue(user.Enabled),
		})
	}
	return result
}

func mapClients(clients []*gocloak.Client) []ClientInfo {
	result := make([]ClientInfo, 0, len(clients))
	for _, client := range clients {
		if client == nil {
			continue
		}
		result = append(result, ClientInfo{
			ID:       stringValue(client.ID),
			ClientID: stringValue(client.ClientID),
			Name:     stringValue(client.Name),
			Enabled:  boolValue(client.Enabled),
			Public:   boolValue(client.PublicClient),
		})
	}
	return result
}

func mapRealm(realm *gocloak.RealmRepresentation) RealmInfo {
	return RealmInfo{
		ID:          stringValue(realm.ID),
		Name:        stringValue(realm.Realm),
		DisplayName: stringValue(realm.DisplayName),
		Enabled:     boolValue(realm.Enabled),
	}
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func boolValue(value *bool) bool {
	return value != nil && *value
}
