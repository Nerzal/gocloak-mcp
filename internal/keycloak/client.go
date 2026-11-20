// Package keycloak provides read-only Keycloak services backed by GoCloak.
package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

// Client is the read-only subset of GoCloak used by the MCP server.
type Client interface {
	GetToken(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error)

	// Users
	GetUsers(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error)
	GetUserByID(context.Context, string, string, string) (*gocloak.User, error)
	GetUserCount(context.Context, string, string, gocloak.GetUsersParams) (int, error)
	GetUserSessions(context.Context, string, string, string) ([]*gocloak.UserSessionRepresentation, error)
	GetUserGroups(context.Context, string, string, string, gocloak.GetGroupsParams) ([]*gocloak.Group, error)
	GetRoleMappingByUserID(context.Context, string, string, string) (*gocloak.MappingsRepresentation, error)

	// Clients & Client Scopes
	GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error)
	GetClient(context.Context, string, string, string) (*gocloak.Client, error)
	GetClientServiceAccount(context.Context, string, string, string) (*gocloak.User, error)
	GetClientRoles(context.Context, string, string, string, gocloak.GetRoleParams) ([]*gocloak.Role, error)
	GetClientScopes(context.Context, string, string) ([]*gocloak.ClientScope, error)
	GetClientScope(context.Context, string, string, string) (*gocloak.ClientScope, error)

	// Roles
	GetRealmRoles(context.Context, string, string, gocloak.GetRoleParams) ([]*gocloak.Role, error)
	GetRealmRole(context.Context, string, string, string) (*gocloak.Role, error)
	GetUsersByRoleName(context.Context, string, string, string, gocloak.GetUsersByRoleParams) ([]*gocloak.User, error)
	GetUsersByClientRoleName(context.Context, string, string, string, string, gocloak.GetUsersByRoleParams) ([]*gocloak.User, error)

	// Groups
	GetGroups(context.Context, string, string, gocloak.GetGroupsParams) ([]*gocloak.Group, error)
	GetGroupsCount(context.Context, string, string, gocloak.GetGroupsParams) (int, error)
	GetGroup(context.Context, string, string, string) (*gocloak.Group, error)
	GetGroupMembers(context.Context, string, string, string, gocloak.GetGroupsParams) ([]*gocloak.User, error)
	GetRoleMappingByGroupID(context.Context, string, string, string) (*gocloak.MappingsRepresentation, error)

	// Realms & Events
	GetRealms(context.Context, string) ([]*gocloak.RealmRepresentation, error)
	GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error)
	GetEvents(context.Context, string, string, gocloak.GetEventsParams) ([]*gocloak.EventRepresentation, error)
	GetAdminEvents(context.Context, string, string, gocloak.GetAdminEventsParams) ([]*gocloak.AdminEventRepresentation, error)

	// Authentication Flows, Required Actions, Identity Providers & Organizations
	GetAuthenticationFlows(context.Context, string, string) ([]*gocloak.AuthenticationFlowRepresentation, error)
	GetAuthenticationExecutions(context.Context, string, string, string) ([]*gocloak.ModifyAuthenticationExecutionRepresentation, error)
	GetRequiredActions(context.Context, string, string) ([]*gocloak.RequiredActionProviderRepresentation, error)
	GetIdentityProviders(context.Context, string, string) ([]*gocloak.IdentityProviderRepresentation, error)
	GetIdentityProvider(context.Context, string, string, string) (*gocloak.IdentityProviderRepresentation, error)
	GetOrganizations(context.Context, string, string, gocloak.GetOrganizationsParams) ([]*gocloak.OrganizationRepresentation, error)
	GetOrganizationMembers(context.Context, string, string, string, gocloak.GetMembersParams) ([]*gocloak.MemberRepresentation, error)
}

// UserFilter defines optional filters for listing or counting users.
type UserFilter struct {
	Search   string
	Username string
	Email    string
	Exact    bool
}

// User contains the safe user fields exposed by the MCP server.
type User struct {
	ID            string `json:"id"`
	Username      string `json:"username,omitempty"`
	Email         string `json:"email,omitempty"`
	FirstName     string `json:"firstName,omitempty"`
	LastName      string `json:"lastName,omitempty"`
	Enabled       bool   `json:"enabled"`
	EmailVerified bool   `json:"emailVerified,omitempty"`
}

// UserSession contains safe metadata for an active Keycloak user session.
type UserSession struct {
	ID         string            `json:"id"`
	UserID     string            `json:"userId,omitempty"`
	Username   string            `json:"username,omitempty"`
	Start      int64             `json:"start,omitempty"`
	LastAccess int64             `json:"lastAccess,omitempty"`
	Clients    map[string]string `json:"clients,omitempty"`
}

// ClientFilter defines optional filters for listing clients.
type ClientFilter struct {
	ClientID string
}

// ClientInfo contains the safe client fields exposed by the MCP server.
type ClientInfo struct {
	ID                     string `json:"id"`
	ClientID               string `json:"clientId,omitempty"`
	Name                   string `json:"name,omitempty"`
	Description            string `json:"description,omitempty"`
	Protocol               string `json:"protocol,omitempty"`
	Enabled                bool   `json:"enabled"`
	Public                 bool   `json:"publicClient"`
	StandardFlowEnabled    bool   `json:"standardFlowEnabled,omitempty"`
	ServiceAccountsEnabled bool   `json:"serviceAccountsEnabled,omitempty"`
	DirectAccessGrants     bool   `json:"directAccessGrantsEnabled,omitempty"`
}

// ClientScopeInfo contains safe client scope fields.
type ClientScopeInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

// RoleInfo contains safe role fields.
type RoleInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite"`
	ClientRole  bool   `json:"clientRole"`
	ContainerID string `json:"containerId,omitempty"`
}

// RoleMappings groups realm-level and client-level role assignments.
type RoleMappings struct {
	RealmRoles  []RoleInfo            `json:"realmRoles"`
	ClientRoles map[string][]RoleInfo `json:"clientRoles,omitempty"`
}

// GroupInfo contains safe group metadata.
type GroupInfo struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

// RealmInfo contains safe realm fields exposed by the MCP server.
type RealmInfo struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"realm"`
	DisplayName string `json:"displayName,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// EventFilter defines optional filters for querying login/user events.
type EventFilter struct {
	Type     []string
	Client   string
	UserID   string
	DateFrom string
	DateTo   string
}

// EventInfo contains safe user/login event fields.
type EventInfo struct {
	Time      int64  `json:"time,omitempty"`
	Type      string `json:"type,omitempty"`
	RealmID   string `json:"realmId,omitempty"`
	ClientID  string `json:"clientId,omitempty"`
	UserID    string `json:"userId,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

// AdminEventFilter defines optional filters for querying admin events.
type AdminEventFilter struct {
	OperationTypes []string
	ResourceTypes  []string
	ResourcePath   string
	DateFrom       string
	DateTo         string
}

// AdminEventInfo contains safe admin event metadata (omits raw representation payloads).
type AdminEventInfo struct {
	Time          int64  `json:"time,omitempty"`
	OperationType string `json:"operationType,omitempty"`
	RealmID       string `json:"realmId,omitempty"`
	ResourceType  string `json:"resourceType,omitempty"`
	ResourcePath  string `json:"resourcePath,omitempty"`
	AuthClientID  string `json:"authClientId,omitempty"`
	AuthUserID    string `json:"authUserId,omitempty"`
}

// AuthFlowInfo contains safe authentication flow metadata.
type AuthFlowInfo struct {
	ID          string `json:"id"`
	Alias       string `json:"alias,omitempty"`
	Description string `json:"description,omitempty"`
	ProviderID  string `json:"providerId,omitempty"`
	TopLevel    bool   `json:"topLevel"`
	BuiltIn     bool   `json:"builtIn"`
}

// FlowExecutionInfo contains safe authentication flow execution metadata.
type FlowExecutionInfo struct {
	ID                 string `json:"id"`
	DisplayName        string `json:"displayName,omitempty"`
	Alias              string `json:"alias,omitempty"`
	ProviderID         string `json:"providerId,omitempty"`
	Requirement        string `json:"requirement,omitempty"`
	Level              int    `json:"level"`
	Index              int    `json:"index"`
	AuthenticationFlow bool   `json:"authenticationFlow"`
	Configurable       bool   `json:"configurable"`
}

// RequiredActionInfo contains safe required-action metadata.
type RequiredActionInfo struct {
	Alias         string `json:"alias"`
	Name          string `json:"name,omitempty"`
	ProviderID    string `json:"providerId,omitempty"`
	Enabled       bool   `json:"enabled"`
	DefaultAction bool   `json:"defaultAction"`
	Priority      int32  `json:"priority"`
}

// IdentityProviderInfo contains safe identity provider metadata (never exposes Config secrets).
type IdentityProviderInfo struct {
	Alias       string `json:"alias"`
	InternalID  string `json:"internalId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	ProviderID  string `json:"providerId,omitempty"`
	Enabled     bool   `json:"enabled"`
	TrustEmail  bool   `json:"trustEmail"`
	LinkOnly    bool   `json:"linkOnly"`
}

// OrganizationInfo contains safe Keycloak 26+ organization metadata.
type OrganizationInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Alias       string   `json:"alias,omitempty"`
	Description string   `json:"description,omitempty"`
	Enabled     bool     `json:"enabled"`
	Domains     []string `json:"domains,omitempty"`
}

// OrganizationMember contains safe member metadata for an organization.
type OrganizationMember struct {
	User
	MembershipType string `json:"membershipType,omitempty"`
}
