package keycloak

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v14"

	"github.com/Nerzal/gocloak-mcp/internal/config"
)

const (
	maxPageSize     = 100
	maxIdentifier   = 255
	maxFilterLength = 255
	maxFilterSlice  = 20
)

var (
	errKeycloakRequest = errors.New("keycloak request failed")
	errUnauthorized    = errors.New("keycloak request unauthorized")
	errRealmNotAllowed = errors.New("realm is not allowed")
	errInvalidPage     = errors.New("invalid pagination parameters")
	errInvalidID       = errors.New("invalid identifier")
	errInvalidFilter   = errors.New("invalid filter parameter")
)

// Service exposes all read-only Keycloak operations used by MCP handlers.
type Service interface {
	// Users
	ListUsers(ctx context.Context, realm string, first, pageSize int, filter UserFilter) ([]User, error)
	GetUser(ctx context.Context, realm, userID string) (User, error)
	CountUsers(ctx context.Context, realm string, filter UserFilter) (int, error)
	GetUserSessions(ctx context.Context, realm, userID string) ([]UserSession, error)
	GetUserGroups(ctx context.Context, realm, userID string, first, pageSize int) ([]GroupInfo, error)
	GetUserRoles(ctx context.Context, realm, userID string) (RoleMappings, error)

	// Clients & Client Scopes
	ListClients(ctx context.Context, realm string, first, pageSize int, filter ClientFilter) ([]ClientInfo, error)
	GetClient(ctx context.Context, realm, clientUUID string) (ClientInfo, error)
	GetClientServiceAccount(ctx context.Context, realm, clientUUID string) (User, error)
	ListClientRoles(ctx context.Context, realm, clientUUID string, first, pageSize int, search string) ([]RoleInfo, error)
	ListClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error)
	GetClientScope(ctx context.Context, realm, scopeID string) (ClientScopeInfo, error)

	// Roles
	ListRealmRoles(ctx context.Context, realm string, first, pageSize int, search string) ([]RoleInfo, error)
	GetRealmRole(ctx context.Context, realm, roleName string) (RoleInfo, error)
	GetUsersInRole(ctx context.Context, realm, roleName string, first, pageSize int) ([]User, error)
	GetUsersInClientRole(ctx context.Context, realm, clientUUID, roleName string, first, pageSize int) ([]User, error)

	// Groups
	ListGroups(ctx context.Context, realm string, first, pageSize int, search string) ([]GroupInfo, error)
	CountGroups(ctx context.Context, realm, search string) (int, error)
	GetGroup(ctx context.Context, realm, groupID string) (GroupInfo, error)
	GetGroupMembers(ctx context.Context, realm, groupID string, first, pageSize int) ([]User, error)
	GetGroupRoles(ctx context.Context, realm, groupID string) (RoleMappings, error)

	// Realms & Events
	ListRealms(ctx context.Context) ([]RealmInfo, error)
	GetRealmInfo(ctx context.Context, realm string) (RealmInfo, error)
	ListEvents(ctx context.Context, realm string, first, pageSize int, filter *EventFilter) ([]EventInfo, error)
	ListAdminEvents(ctx context.Context, realm string, first, pageSize int, filter *AdminEventFilter) ([]AdminEventInfo, error)

	// Authentication Flows, Required Actions, Identity Providers & Organizations
	ListAuthenticationFlows(ctx context.Context, realm string) ([]AuthFlowInfo, error)
	GetFlowExecutions(ctx context.Context, realm, flowAlias string) ([]FlowExecutionInfo, error)
	ListRequiredActions(ctx context.Context, realm string) ([]RequiredActionInfo, error)
	ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProviderInfo, error)
	GetIdentityProvider(ctx context.Context, realm, alias string) (IdentityProviderInfo, error)
	ListOrganizations(ctx context.Context, realm string, first, pageSize int, search string) ([]OrganizationInfo, error)
	GetOrganizationMembers(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]OrganizationMember, error)
}

type service struct {
	client        Client
	tokens        TokenProvider
	defaultRealm  string
	allowedRealms map[string]struct{}
}

// NewService constructs a Keycloak service with a default realm and explicit realm allowlist.
func NewService(client Client, tokens TokenProvider, defaultRealm string, allowedRealms []string) Service {
	allowed := make(map[string]struct{}, len(allowedRealms)+1)
	if defaultRealm != "" {
		allowed[defaultRealm] = struct{}{}
	}
	for _, realm := range allowedRealms {
		if realm != "" {
			allowed[realm] = struct{}{}
		}
	}
	return &service{
		client:        client,
		tokens:        tokens,
		defaultRealm:  defaultRealm,
		allowedRealms: allowed,
	}
}

func (s *service) resolveRealm(realm string) (string, error) {
	if realm == "" {
		return s.defaultRealm, nil
	}
	if !config.IsValidRealm(realm) {
		return "", errRealmNotAllowed
	}
	if _, ok := s.allowedRealms[realm]; !ok {
		return "", errRealmNotAllowed
	}
	return realm, nil
}

func runWithTokenRetry[T any](ctx context.Context, tokens TokenProvider, call func(string) (T, error)) (T, error) {
	var zero T
	token, err := tokens.Token(ctx)
	if err != nil {
		return zero, errKeycloakRequest
	}
	result, err := call(token)
	if !errors.Is(err, errUnauthorized) {
		if err != nil {
			return zero, errKeycloakRequest
		}
		return result, nil
	}
	tokens.Invalidate()
	freshToken, err := tokens.Token(ctx)
	if err != nil {
		return zero, errKeycloakRequest
	}
	result, err = call(freshToken)
	if err != nil {
		return zero, errKeycloakRequest
	}
	return result, nil
}

func classifyUpstreamError(err error) error {
	var apiErr *gocloak.APIError
	if errors.As(err, &apiErr) && apiErr.Code == http.StatusUnauthorized {
		return errUnauthorized
	}
	return errKeycloakRequest
}

func validatePagination(first, pageSize int) error {
	if first < 0 || pageSize < 1 || pageSize > maxPageSize {
		return errInvalidPage
	}
	return nil
}

func validateIdentifier(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > maxIdentifier || trimmed == "." || trimmed == ".." ||
		strings.ContainsAny(trimmed, "/\\?#\r\n") {
		return errInvalidID
	}
	return nil
}

func validateFilterString(value string) error {
	if len(value) > maxFilterLength || strings.ContainsAny(value, "\r\n") {
		return errInvalidFilter
	}
	return nil
}

func validateFilterSlice(values []string) error {
	if len(values) > maxFilterSlice {
		return errInvalidFilter
	}
	for _, value := range values {
		if err := validateFilterString(value); err != nil {
			return err
		}
	}
	return nil
}

func optionalStringPtr(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func derefString(ptr *string) string {
	if ptr == nil {
		return ""
	}
	return *ptr
}

func derefBool(ptr *bool) bool {
	if ptr == nil {
		return false
	}
	return *ptr
}

func derefInt(ptr *int) int {
	if ptr == nil {
		return 0
	}
	return *ptr
}

func derefInt32(ptr *int32) int32 {
	if ptr == nil {
		return 0
	}
	return *ptr
}

func derefInt64(ptr *int64) int64 {
	if ptr == nil {
		return 0
	}
	return *ptr
}
