package keycloak

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

// UserSession contains safe metadata for an active or offline Keycloak user session.
type UserSession struct {
	ID         string            `json:"id"`
	UserID     string            `json:"userId,omitempty"`
	Username   string            `json:"username,omitempty"`
	Start      int64             `json:"start,omitempty"`
	LastAccess int64             `json:"lastAccess,omitempty"`
	Clients    map[string]string `json:"clients,omitempty"`
}

// UserCredentialInfo contains safe credential metadata (never exposes secretData, credentialData, value, or hashes).
type UserCredentialInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type,omitempty"`
	UserLabel   string `json:"userLabel,omitempty"`
	CreatedDate int64  `json:"createdDate,omitempty"`
	Priority    int32  `json:"priority,omitempty"`
	Temporary   bool   `json:"temporary,omitempty"`
}

// FederatedIdentityInfo contains safe federated identity link metadata for a user.
type FederatedIdentityInfo struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId,omitempty"`
	UserName         string `json:"userName,omitempty"`
}

// BruteForceStatusInfo contains attack-detection lockout metadata for a user.
type BruteForceStatusInfo struct {
	NumFailures   int    `json:"numFailures"`
	Disabled      bool   `json:"disabled"`
	LastIPFailure string `json:"lastIpFailure,omitempty"`
	LastFailure   int    `json:"lastFailure,omitempty"`
}

// ClientFilter defines optional filters for listing clients.
type ClientFilter struct {
	ClientID string
}

// ClientInfo contains the safe client fields exposed by the MCP server (never exposes secret or registrationAccessToken).
type ClientInfo struct {
	ID                           string   `json:"id"`
	ClientID                     string   `json:"clientId,omitempty"`
	Name                         string   `json:"name,omitempty"`
	Description                  string   `json:"description,omitempty"`
	Protocol                     string   `json:"protocol,omitempty"`
	Enabled                      bool     `json:"enabled"`
	Public                       bool     `json:"publicClient"`
	BearerOnly                   bool     `json:"bearerOnly,omitempty"`
	ConsentRequired              bool     `json:"consentRequired,omitempty"`
	StandardFlowEnabled          bool     `json:"standardFlowEnabled,omitempty"`
	ImplicitFlowEnabled          bool     `json:"implicitFlowEnabled,omitempty"`
	ServiceAccountsEnabled       bool     `json:"serviceAccountsEnabled,omitempty"`
	DirectAccessGrants           bool     `json:"directAccessGrantsEnabled,omitempty"`
	AuthorizationServicesEnabled bool     `json:"authorizationServicesEnabled,omitempty"`
	FullScopeAllowed             bool     `json:"fullScopeAllowed,omitempty"`
	RootURL                      string   `json:"rootUrl,omitempty"`
	BaseURL                      string   `json:"baseUrl,omitempty"`
	RedirectURIs                 []string `json:"redirectUris,omitempty"`
	WebOrigins                   []string `json:"webOrigins,omitempty"`
}

// ClientScopeInfo contains safe client scope fields.
type ClientScopeInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

// ProtocolMapperInfo contains safe protocol mapper metadata (omits scripts and sensitive config keys).
type ProtocolMapperInfo struct {
	ID              string            `json:"id"`
	Name            string            `json:"name,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	ProtocolMapper  string            `json:"protocolMapper,omitempty"`
	ConsentRequired bool              `json:"consentRequired,omitempty"`
	Config          map[string]string `json:"config,omitempty"`
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

// RealmInfo contains safe realm configuration and security posture fields (never exposes SMTP or secret configs).
type RealmInfo struct {
	ID                          string `json:"id,omitempty"`
	Name                        string `json:"realm"`
	DisplayName                 string `json:"displayName,omitempty"`
	Enabled                     bool   `json:"enabled"`
	SSLRequired                 string `json:"sslRequired,omitempty"`
	BruteForceProtected         bool   `json:"bruteForceProtected,omitempty"`
	RegistrationAllowed         bool   `json:"registrationAllowed,omitempty"`
	ResetPasswordAllowed        bool   `json:"resetPasswordAllowed,omitempty"`
	RememberMe                  bool   `json:"rememberMe,omitempty"`
	VerifyEmail                 bool   `json:"verifyEmail,omitempty"`
	LoginWithEmailAllowed       bool   `json:"loginWithEmailAllowed,omitempty"`
	DuplicateEmailsAllowed      bool   `json:"duplicateEmailsAllowed,omitempty"`
	EventsEnabled               bool   `json:"eventsEnabled,omitempty"`
	AdminEventsEnabled          bool   `json:"adminEventsEnabled,omitempty"`
	PasswordPolicy              string `json:"passwordPolicy,omitempty"`
	DefaultSignatureAlgorithm   string `json:"defaultSignatureAlgorithm,omitempty"`
	BrowserFlow                 string `json:"browserFlow,omitempty"`
	DirectGrantFlow             string `json:"directGrantFlow,omitempty"`
	RegistrationFlow            string `json:"registrationFlow,omitempty"`
	OrganizationsEnabled        bool   `json:"organizationsEnabled,omitempty"`
	InternationalizationEnabled bool   `json:"internationalizationEnabled,omitempty"`
	DefaultLocale               string `json:"defaultLocale,omitempty"`
	LoginTheme                  string `json:"loginTheme,omitempty"`
	AccessTokenLifespan         int    `json:"accessTokenLifespan,omitempty"`
	SSOSessionIdleTimeout       int    `json:"ssoSessionIdleTimeout,omitempty"`
	SSOSessionMaxLifespan       int    `json:"ssoSessionMaxLifespan,omitempty"`
}

// RealmKeyInfo contains safe public key metadata from a realm keystore.
type RealmKeyInfo struct {
	ProviderID       string `json:"providerId,omitempty"`
	ProviderPriority int    `json:"providerPriority,omitempty"`
	Kid              string `json:"kid,omitempty"`
	Status           string `json:"status,omitempty"`
	Type             string `json:"type,omitempty"`
	Algorithm        string `json:"algorithm,omitempty"`
	PublicKey        string `json:"publicKey,omitempty"`
}

// RealmKeysInfo contains active key IDs and public key metadata for a realm.
type RealmKeysInfo struct {
	ActiveHS256 string         `json:"activeHs256,omitempty"`
	ActiveRS256 string         `json:"activeRs256,omitempty"`
	ActiveAES   string         `json:"activeAes,omitempty"`
	Keys        []RealmKeyInfo `json:"keys"`
}

// JWKInfo contains public OIDC JWK metadata from the realm certs endpoint.
type JWKInfo struct {
	Kid     string   `json:"kid,omitempty"`
	Kty     string   `json:"kty,omitempty"`
	Alg     string   `json:"alg,omitempty"`
	Use     string   `json:"use,omitempty"`
	Crv     string   `json:"crv,omitempty"`
	KeyOps  []string `json:"keyOps,omitempty"`
	X5t     string   `json:"x5t,omitempty"`
	X5tS256 string   `json:"x5tS256,omitempty"`
}

// RealmIssuerInfo contains public OIDC issuer metadata for a realm.
type RealmIssuerInfo struct {
	Realm           string `json:"realm"`
	PublicKey       string `json:"publicKey,omitempty"`
	TokenService    string `json:"tokenService,omitempty"`
	AccountService  string `json:"accountService,omitempty"`
	TokensNotBefore int    `json:"tokensNotBefore,omitempty"`
}

// UserProfileAttributeInfo contains safe metadata for a configured user profile attribute.
type UserProfileAttributeInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Group       string `json:"group,omitempty"`
	MultiValued bool   `json:"multivalued,omitempty"`
}

// UserProfileGroupInfo contains safe metadata for a user profile attribute group.
type UserProfileGroupInfo struct {
	Name               string `json:"name"`
	DisplayHeader      string `json:"displayHeader,omitempty"`
	DisplayDescription string `json:"displayDescription,omitempty"`
}

// UserProfileConfigInfo contains safe realm user profile schema metadata.
type UserProfileConfigInfo struct {
	UnmanagedAttributePolicy string                     `json:"unmanagedAttributePolicy,omitempty"`
	Attributes               []UserProfileAttributeInfo `json:"attributes"`
	Groups                   []UserProfileGroupInfo     `json:"groups,omitempty"`
}

// ServerInfo contains safe Keycloak server version and runtime metadata.
type ServerInfo struct {
	Version    string `json:"version,omitempty"`
	ServerTime string `json:"serverTime,omitempty"`
	Uptime     string `json:"uptime,omitempty"`
	JavaVendor string `json:"javaVendor,omitempty"`
	JavaVM     string `json:"javaVm,omitempty"`
	OSName     string `json:"osName,omitempty"`
	OSArch     string `json:"osArch,omitempty"`
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

// AuthenticatorConfigInfo contains safe authenticator config metadata (redacts secret/password/token/key entries).
type AuthenticatorConfigInfo struct {
	ID     string            `json:"id"`
	Alias  string            `json:"alias,omitempty"`
	Config map[string]string `json:"config,omitempty"`
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

// UnregisteredRequiredActionInfo contains metadata for an available unregistered required action.
type UnregisteredRequiredActionInfo struct {
	Name       string `json:"name,omitempty"`
	ProviderID string `json:"providerId"`
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

// IdentityProviderMapperInfo contains safe identity provider mapper metadata (redacts sensitive config keys).
type IdentityProviderMapperInfo struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name,omitempty"`
	IdentityProviderMapper string            `json:"identityProviderMapper,omitempty"`
	IdentityProviderAlias  string            `json:"identityProviderAlias,omitempty"`
	Config                 map[string]string `json:"config,omitempty"`
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

// OrganizationInvitationInfo contains safe invitation metadata (never exposes inviteLink bearer tokens).
type OrganizationInvitationInfo struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organizationId,omitempty"`
	Email          string `json:"email,omitempty"`
	FirstName      string `json:"firstName,omitempty"`
	LastName       string `json:"lastName,omitempty"`
	SentDate       int64  `json:"sentDate,omitempty"`
	ExpiresAt      int64  `json:"expiresAt,omitempty"`
	Status         string `json:"status,omitempty"`
}

// ComponentFilter defines optional filters for listing realm components (e.g. LDAP/Kerberos federation providers).
type ComponentFilter struct {
	Name         string
	ProviderType string
	ParentID     string
}

// ComponentInfo contains safe realm component metadata (never exposes ComponentConfig secrets like bindCredential).
type ComponentInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name,omitempty"`
	ProviderID   string `json:"providerId,omitempty"`
	ProviderType string `json:"providerType,omitempty"`
	ParentID     string `json:"parentId,omitempty"`
	SubType      string `json:"subType,omitempty"`
}

// ResourceServerInfo contains safe fine-grained authorization server settings for a client.
type ResourceServerInfo struct {
	ID                            string `json:"id,omitempty"`
	ClientID                      string `json:"clientId,omitempty"`
	Name                          string `json:"name,omitempty"`
	AllowRemoteResourceManagement bool   `json:"allowRemoteResourceManagement"`
	PolicyEnforcementMode         string `json:"policyEnforcementMode,omitempty"`
	DecisionStrategy              string `json:"decisionStrategy,omitempty"`
}

// AuthzResourceFilter defines optional filters for listing authorization resources.
type AuthzResourceFilter struct {
	Name  string
	Owner string
	Type  string
	URI   string
	Scope string
}

// AuthzResourceInfo contains safe metadata for a fine-grained authorization resource.
type AuthzResourceInfo struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name,omitempty"`
	DisplayName        string   `json:"displayName,omitempty"`
	Type               string   `json:"type,omitempty"`
	IconURI            string   `json:"iconUri,omitempty"`
	OwnerManagedAccess bool     `json:"ownerManagedAccess,omitempty"`
	URIs               []string `json:"uris,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
}

// AuthzScopeInfo contains safe metadata for a fine-grained authorization scope.
type AuthzScopeInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	IconURI     string `json:"iconUri,omitempty"`
}

// AuthzPolicyFilter defines optional filters for listing authorization policies.
type AuthzPolicyFilter struct {
	Name string
	Type string
}

// AuthzPolicyInfo contains safe metadata for a fine-grained authorization policy.
type AuthzPolicyInfo struct {
	ID               string   `json:"id"`
	Name             string   `json:"name,omitempty"`
	Description      string   `json:"description,omitempty"`
	Type             string   `json:"type,omitempty"`
	Logic            string   `json:"logic,omitempty"`
	DecisionStrategy string   `json:"decisionStrategy,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	Policies         []string `json:"policies,omitempty"`
}

// AuthzPermissionFilter defines optional filters for listing authorization permissions.
type AuthzPermissionFilter struct {
	Name     string
	Resource string
	Scope    string
	Type     string
}

// AuthzPermissionInfo contains safe metadata for a fine-grained authorization permission.
type AuthzPermissionInfo struct {
	ID               string   `json:"id"`
	Name             string   `json:"name,omitempty"`
	Description      string   `json:"description,omitempty"`
	Type             string   `json:"type,omitempty"`
	ResourceType     string   `json:"resourceType,omitempty"`
	Logic            string   `json:"logic,omitempty"`
	DecisionStrategy string   `json:"decisionStrategy,omitempty"`
	Resources        []string `json:"resources,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	Policies         []string `json:"policies,omitempty"`
}

// NamedRef is a compact safe ID + Name reference (used for policy resources/scopes).
type NamedRef struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}
