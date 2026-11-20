// Package keycloak provides read-only Keycloak services backed by GoCloak.
package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

// Client is the subset of GoCloak used by the read-only server.
type Client interface {
	GetToken(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error)
	GetUsers(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error)
	GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error)
	GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error)
}

// User contains the user fields exposed by the MCP server.
type User struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Enabled  bool   `json:"enabled"`
}

// ClientInfo contains the client fields exposed by the MCP server.
type ClientInfo struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId,omitempty"`
	Name     string `json:"name,omitempty"`
	Enabled  bool   `json:"enabled"`
	Public   bool   `json:"publicClient"`
}

// RealmInfo contains the realm fields exposed by the MCP server.
type RealmInfo struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"realm"`
	DisplayName string `json:"displayName,omitempty"`
	Enabled     bool   `json:"enabled"`
}
