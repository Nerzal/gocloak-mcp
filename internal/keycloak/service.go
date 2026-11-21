package keycloak

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v15"

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
	// Users & Attack Detection
	ListUsers(ctx context.Context, realm string, first, pageSize int, filter UserFilter) ([]User, error)
	GetUser(ctx context.Context, realm, userID string) (User, error)
	CountUsers(ctx context.Context, realm string, filter UserFilter) (int, error)
	GetUserSessions(ctx context.Context, realm, userID string) ([]UserSession, error)
	GetUserOfflineSessions(ctx context.Context, realm, userID, clientUUID string) ([]UserSession, error)
	GetUserGroups(ctx context.Context, realm, userID string, first, pageSize int) ([]GroupInfo, error)
	GetUserRoles(ctx context.Context, realm, userID string) (RoleMappings, error)
	GetUserCredentials(ctx context.Context, realm, userID string) ([]UserCredentialInfo, error)
	GetUserFederatedIdentities(ctx context.Context, realm, userID string) ([]FederatedIdentityInfo, error)
	GetUserBruteForceStatus(ctx context.Context, realm, userID string) (BruteForceStatusInfo, error)
	GetUserCompositeRealmRoles(ctx context.Context, realm, userID string) ([]RoleInfo, error)
	GetUserCompositeClientRoles(ctx context.Context, realm, userID, clientUUID string) ([]RoleInfo, error)
	GetUserAvailableRealmRoles(ctx context.Context, realm, userID string) ([]RoleInfo, error)
	GetUserAvailableClientRoles(ctx context.Context, realm, userID, clientUUID string) ([]RoleInfo, error)

	// Clients & Client Scopes
	ListClients(ctx context.Context, realm string, first, pageSize int, filter ClientFilter) ([]ClientInfo, error)
	GetClient(ctx context.Context, realm, clientUUID string) (ClientInfo, error)
	GetClientServiceAccount(ctx context.Context, realm, clientUUID string) (User, error)
	ListClientRoles(ctx context.Context, realm, clientUUID string, first, pageSize int, search string) ([]RoleInfo, error)
	GetClientRole(ctx context.Context, realm, clientUUID, roleName string) (RoleInfo, error)
	GetClientProtocolMappers(ctx context.Context, realm, clientUUID string) ([]ProtocolMapperInfo, error)
	GetClientDefaultScopes(ctx context.Context, realm, clientUUID string) ([]ClientScopeInfo, error)
	GetClientOptionalScopes(ctx context.Context, realm, clientUUID string) ([]ClientScopeInfo, error)
	GetClientScopeMappings(ctx context.Context, realm, clientUUID string) (RoleMappings, error)
	GetClientSessions(ctx context.Context, realm, clientUUID string, first, pageSize int) ([]UserSession, error)
	GetClientOfflineSessions(ctx context.Context, realm, clientUUID string, first, pageSize int) ([]UserSession, error)
	ListClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error)
	GetClientScope(ctx context.Context, realm, scopeID string) (ClientScopeInfo, error)
	ListClientScopeProtocolMappers(ctx context.Context, realm, scopeID string) ([]ProtocolMapperInfo, error)
	GetClientScopeProtocolMapper(ctx context.Context, realm, scopeID, mapperID string) (ProtocolMapperInfo, error)
	GetDefaultDefaultClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error)
	GetDefaultOptionalClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error)
	GetClientScopeRealmRoles(ctx context.Context, realm, scopeID string) ([]RoleInfo, error)
	GetClientScopeClientRoles(ctx context.Context, realm, scopeID, clientUUID string) ([]RoleInfo, error)

	// Roles
	ListRealmRoles(ctx context.Context, realm string, first, pageSize int, search string) ([]RoleInfo, error)
	GetRealmRole(ctx context.Context, realm, roleName string) (RoleInfo, error)
	GetRoleByID(ctx context.Context, realm, roleID string) (RoleInfo, error)
	GetRealmRoleComposites(ctx context.Context, realm, roleName string) ([]RoleInfo, error)
	GetRoleCompositesByID(ctx context.Context, realm, roleID string) ([]RoleInfo, error)
	GetUsersInRole(ctx context.Context, realm, roleName string, first, pageSize int) ([]User, error)
	GetUsersInClientRole(ctx context.Context, realm, clientUUID, roleName string, first, pageSize int) ([]User, error)
	GetGroupsInRole(ctx context.Context, realm, roleName string) ([]GroupInfo, error)
	GetGroupsInClientRole(ctx context.Context, realm, clientUUID, roleName string) ([]GroupInfo, error)

	// Groups
	ListGroups(ctx context.Context, realm string, first, pageSize int, search string) ([]GroupInfo, error)
	CountGroups(ctx context.Context, realm, search string) (int, error)
	GetGroup(ctx context.Context, realm, groupID string) (GroupInfo, error)
	GetGroupByPath(ctx context.Context, realm, groupPath string) (GroupInfo, error)
	ListChildGroups(ctx context.Context, realm, groupID string, first, pageSize int, search string) ([]GroupInfo, error)
	GetDefaultGroups(ctx context.Context, realm string) ([]GroupInfo, error)
	GetGroupMembers(ctx context.Context, realm, groupID string, first, pageSize int) ([]User, error)
	GetGroupRoles(ctx context.Context, realm, groupID string) (RoleMappings, error)
	GetGroupCompositeRealmRoles(ctx context.Context, realm, groupID string) ([]RoleInfo, error)
	GetGroupCompositeClientRoles(ctx context.Context, realm, groupID, clientUUID string) ([]RoleInfo, error)
	GetGroupAvailableRealmRoles(ctx context.Context, realm, groupID string) ([]RoleInfo, error)
	GetGroupAvailableClientRoles(ctx context.Context, realm, groupID, clientUUID string) ([]RoleInfo, error)

	// Realms, Keys, Events & Server Info
	ListRealms(ctx context.Context) ([]RealmInfo, error)
	GetRealmInfo(ctx context.Context, realm string) (RealmInfo, error)
	ListEvents(ctx context.Context, realm string, first, pageSize int, filter *EventFilter) ([]EventInfo, error)
	ListAdminEvents(ctx context.Context, realm string, first, pageSize int, filter *AdminEventFilter) ([]AdminEventInfo, error)
	GetRealmKeys(ctx context.Context, realm string) (RealmKeysInfo, error)
	GetRealmCerts(ctx context.Context, realm string) ([]JWKInfo, error)
	GetRealmIssuer(ctx context.Context, realm string) (RealmIssuerInfo, error)
	GetUserProfileConfig(ctx context.Context, realm string) (UserProfileConfigInfo, error)
	GetServerInfo(ctx context.Context) (ServerInfo, error)

	// Authentication Flows, Required Actions & Identity Providers
	ListAuthenticationFlows(ctx context.Context, realm string) ([]AuthFlowInfo, error)
	GetAuthenticationFlow(ctx context.Context, realm, flowID string) (AuthFlowInfo, error)
	GetFlowExecutions(ctx context.Context, realm, flowAlias string) ([]FlowExecutionInfo, error)
	GetAuthenticatorConfig(ctx context.Context, realm, configID string) (AuthenticatorConfigInfo, error)
	ListRequiredActions(ctx context.Context, realm string) ([]RequiredActionInfo, error)
	GetRequiredAction(ctx context.Context, realm, alias string) (RequiredActionInfo, error)
	ListUnregisteredRequiredActions(ctx context.Context, realm string) ([]UnregisteredRequiredActionInfo, error)
	ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProviderInfo, error)
	GetIdentityProvider(ctx context.Context, realm, alias string) (IdentityProviderInfo, error)
	ListIdentityProviderMappers(ctx context.Context, realm, alias string) ([]IdentityProviderMapperInfo, error)
	GetIdentityProviderMapper(ctx context.Context, realm, alias, mapperID string) (IdentityProviderMapperInfo, error)

	// Organizations (Keycloak 26+)
	ListOrganizations(ctx context.Context, realm string, first, pageSize int, search string) ([]OrganizationInfo, error)
	GetOrganization(ctx context.Context, realm, orgID string) (OrganizationInfo, error)
	CountOrganizations(ctx context.Context, realm, search string) (int64, error)
	GetOrganizationMembers(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]OrganizationMember, error)
	CountOrganizationMembers(ctx context.Context, realm, orgID string) (int, error)
	GetOrganizationMember(ctx context.Context, realm, orgID, userID string) (OrganizationMember, error)
	GetUserOrganizations(ctx context.Context, realm, userID string) ([]OrganizationInfo, error)
	ListOrganizationIdentityProviders(ctx context.Context, realm, orgID string) ([]IdentityProviderInfo, error)
	ListOrganizationInvitations(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]OrganizationInvitationInfo, error)
	ListOrganizationGroups(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]GroupInfo, error)

	// Components / User Federation
	ListComponents(ctx context.Context, realm string, filter ComponentFilter) ([]ComponentInfo, error)
	GetComponent(ctx context.Context, realm, componentID string) (ComponentInfo, error)

	// Fine-Grained Authorization Services
	GetResourceServer(ctx context.Context, realm, clientUUID string) (ResourceServerInfo, error)
	ListAuthzResources(ctx context.Context, realm, clientUUID string, first, pageSize int, filter *AuthzResourceFilter) ([]AuthzResourceInfo, error)
	GetAuthzResource(ctx context.Context, realm, clientUUID, resourceID string) (AuthzResourceInfo, error)
	ListAuthzScopes(ctx context.Context, realm, clientUUID string, first, pageSize int, name string) ([]AuthzScopeInfo, error)
	GetAuthzScope(ctx context.Context, realm, clientUUID, scopeID string) (AuthzScopeInfo, error)
	ListAuthzPolicies(ctx context.Context, realm, clientUUID string, first, pageSize int, filter AuthzPolicyFilter) ([]AuthzPolicyInfo, error)
	GetAuthzPolicy(ctx context.Context, realm, clientUUID, policyID string) (AuthzPolicyInfo, error)
	ListAuthzPermissions(ctx context.Context, realm, clientUUID string, first, pageSize int, filter AuthzPermissionFilter) ([]AuthzPermissionInfo, error)
	GetAuthzPermission(ctx context.Context, realm, clientUUID, permissionID string) (AuthzPermissionInfo, error)
	GetPolicyAssociatedPolicies(ctx context.Context, realm, clientUUID, policyID string) ([]AuthzPolicyInfo, error)
	GetPolicyResources(ctx context.Context, realm, clientUUID, policyID string) ([]NamedRef, error)
	GetPolicyScopes(ctx context.Context, realm, clientUUID, policyID string) ([]NamedRef, error)
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

const maxOutputFieldLen = 512

func validateIdentifier(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || value != trimmed || len(trimmed) > maxIdentifier ||
		trimmed == "." || trimmed == ".." ||
		strings.ContainsAny(trimmed, "/\\?#%") || hasControlChar(trimmed) {
		return errInvalidID
	}
	return nil
}

func validateGroupPath(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || value != trimmed || len(trimmed) > maxIdentifier {
		return errInvalidID
	}
	if strings.ContainsAny(trimmed, "\\?#%") || hasControlChar(trimmed) {
		return errInvalidID
	}
	return validateGroupPathSegments(strings.TrimPrefix(trimmed, "/"))
}

func validateGroupPathSegments(path string) error {
	if path == "" {
		return errInvalidID
	}
	for seg := range strings.SplitSeq(path, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errInvalidID
		}
	}
	return nil
}

func validateFilterString(value string) error {
	if len(value) > maxFilterLength || hasControlChar(value) {
		return errInvalidFilter
	}
	return nil
}

func hasControlChar(s string) bool {
	for i := range len(s) {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
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
	return sanitizeOutputString(*ptr)
}

func sanitizeOutputString(s string) string {
	if isCleanShortString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(min(len(s), maxOutputFieldLen))
	count := 0
	for _, r := range s {
		if isUnsafeOutputRune(r) {
			continue
		}
		if count >= maxOutputFieldLen {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func isCleanShortString(s string) bool {
	if len(s) > maxOutputFieldLen {
		return false
	}
	for _, r := range s {
		if isUnsafeOutputRune(r) {
			return false
		}
	}
	return true
}

func isUnsafeOutputRune(r rune) bool {
	if (r < 0x20 && r != '\t') || r == 0x7f {
		return true
	}
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func sanitizeStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, v := range values {
		if clean := sanitizeOutputString(v); clean != "" {
			result = append(result, clean)
		}
	}
	return result
}

func isSensitiveConfigKey(key string) bool {
	lower := strings.ToLower(key)
	switch lower {
	case "id.token.claim", "access.token.claim", "userinfo.token.claim", "introspection.token.claim":
		return false
	}
	for _, marker := range [...]string{
		"secret", "password", "credential", "private", "script",
		"token", "jwt", "pem", "pkcs", "client_assertion",
		"apikey", "api_key", "api-key", "passphrase", "signingkey",
		"signing_key", "encryptionkey", "encryption_key", "bearer",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isSensitiveConfigValue(val string) bool {
	trimmed := strings.TrimSpace(val)
	if len(trimmed) >= 7 && strings.EqualFold(trimmed[:7], "bearer ") {
		return true
	}
	return strings.HasPrefix(trimmed, "eyJ") && strings.Count(trimmed, ".") == 2
}

func sanitizeConfigMap(cfg map[string]string) map[string]string {
	if len(cfg) == 0 {
		return nil
	}
	result := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if isSensitiveConfigKey(k) || isSensitiveConfigValue(v) {
			continue
		}
		result[sanitizeOutputString(k)] = sanitizeOutputString(v)
	}
	if len(result) == 0 {
		return nil
	}
	return result
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
