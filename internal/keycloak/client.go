package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

type Client interface {
	GetToken(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error)
	GetUsers(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error)
	GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error)
	GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error)
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Enabled  bool   `json:"enabled"`
}

type ClientInfo struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId,omitempty"`
	Name     string `json:"name,omitempty"`
	Enabled  bool   `json:"enabled"`
	Public   bool   `json:"publicClient"`
}

type RealmInfo struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"realm"`
	DisplayName string `json:"displayName,omitempty"`
	Enabled     bool   `json:"enabled"`
}
