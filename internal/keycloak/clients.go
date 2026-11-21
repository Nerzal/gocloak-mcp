package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v15"
)

func (s *service) ListClients(ctx context.Context, realm string, first, pageSize int, filter ClientFilter) ([]ClientInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	if valErr := validateFilterString(filter.ClientID); valErr != nil {
		return nil, valErr
	}
	clients, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Client, error) {
		return s.fetchClients(ctx, token, targetRealm, first, pageSize, filter)
	})
	if err != nil {
		return nil, err
	}
	return mapClients(clients), nil
}

func (s *service) GetClient(ctx context.Context, realm, clientUUID string) (ClientInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return ClientInfo{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return ClientInfo{}, valErr
	}
	client, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.Client, error) {
		return s.fetchClient(ctx, token, targetRealm, clientUUID)
	})
	if err != nil {
		return ClientInfo{}, err
	}
	return mapClient(client), nil
}

func (s *service) GetClientServiceAccount(ctx context.Context, realm, clientUUID string) (User, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return User{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return User{}, valErr
	}
	user, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.User, error) {
		return s.fetchClientServiceAccount(ctx, token, targetRealm, clientUUID)
	})
	if err != nil {
		return User{}, err
	}
	return mapUser(user), nil
}

func (s *service) ListClientRoles(ctx context.Context, realm, clientUUID string, first, pageSize int, search string) ([]RoleInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	if valErr := validateFilterString(search); valErr != nil {
		return nil, valErr
	}
	roles, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Role, error) {
		return s.fetchClientRoles(ctx, token, targetRealm, clientUUID, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapRoles(roles), nil
}

func (s *service) GetClientRole(ctx context.Context, realm, clientUUID, roleName string) (RoleInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RoleInfo{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return RoleInfo{}, valErr
	}
	if valErr := validateIdentifier(roleName); valErr != nil {
		return RoleInfo{}, valErr
	}
	role, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.Role, error) {
		res, callErr := s.client.GetClientRole(ctx, token, targetRealm, clientUUID, roleName)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return RoleInfo{}, err
	}
	return mapRole(role), nil
}

func (s *service) GetClientProtocolMappers(ctx context.Context, realm, clientUUID string) ([]ProtocolMapperInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	client, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.Client, error) {
		return s.fetchClient(ctx, token, targetRealm, clientUUID)
	})
	if err != nil {
		return nil, err
	}
	return mapClientProtocolMappers(client.ProtocolMappers), nil
}

func (s *service) GetClientDefaultScopes(ctx context.Context, realm, clientUUID string) ([]ClientScopeInfo, error) {
	return s.fetchClientScopesForID(ctx, realm, clientUUID, func(token, targetRealm string) ([]*gocloak.ClientScope, error) {
		return s.client.GetClientsDefaultScopes(ctx, token, targetRealm, clientUUID)
	})
}

func (s *service) GetClientOptionalScopes(ctx context.Context, realm, clientUUID string) ([]ClientScopeInfo, error) {
	return s.fetchClientScopesForID(ctx, realm, clientUUID, func(token, targetRealm string) ([]*gocloak.ClientScope, error) {
		return s.client.GetClientsOptionalScopes(ctx, token, targetRealm, clientUUID)
	})
}

func (s *service) GetClientScopeMappings(ctx context.Context, realm, clientUUID string) (RoleMappings, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RoleMappings{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return RoleMappings{}, valErr
	}
	mappings, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.MappingsRepresentation, error) {
		res, callErr := s.client.GetClientScopeMappings(ctx, token, targetRealm, clientUUID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return RoleMappings{}, err
	}
	return mapRoleMappings(mappings), nil
}

func (s *service) GetClientSessions(ctx context.Context, realm, clientUUID string, first, pageSize int) ([]UserSession, error) {
	return s.fetchClientSessionList(ctx, realm, clientUUID, first, pageSize, s.client.GetClientUserSessions)
}

func (s *service) GetClientOfflineSessions(ctx context.Context, realm, clientUUID string, first, pageSize int) ([]UserSession, error) {
	return s.fetchClientSessionList(ctx, realm, clientUUID, first, pageSize, s.client.GetClientOfflineSessions)
}

func (s *service) ListClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error) {
	return s.fetchRealmClientScopes(ctx, realm, s.client.GetClientScopes)
}

func (s *service) GetClientScope(ctx context.Context, realm, scopeID string) (ClientScopeInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return ClientScopeInfo{}, err
	}
	if valErr := validateIdentifier(scopeID); valErr != nil {
		return ClientScopeInfo{}, valErr
	}
	scope, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.ClientScope, error) {
		return s.fetchClientScope(ctx, token, targetRealm, scopeID)
	})
	if err != nil {
		return ClientScopeInfo{}, err
	}
	return mapClientScope(scope), nil
}

func (s *service) ListClientScopeProtocolMappers(ctx context.Context, realm, scopeID string) ([]ProtocolMapperInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(scopeID); valErr != nil {
		return nil, valErr
	}
	mappers, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ProtocolMappers, error) {
		res, callErr := s.client.GetClientScopeProtocolMappers(ctx, token, targetRealm, scopeID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapScopeProtocolMappers(mappers), nil
}

func (s *service) GetClientScopeProtocolMapper(ctx context.Context, realm, scopeID, mapperID string) (ProtocolMapperInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return ProtocolMapperInfo{}, err
	}
	if valErr := validateIdentifier(scopeID); valErr != nil {
		return ProtocolMapperInfo{}, valErr
	}
	if valErr := validateIdentifier(mapperID); valErr != nil {
		return ProtocolMapperInfo{}, valErr
	}
	mapper, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.ProtocolMappers, error) {
		res, callErr := s.client.GetClientScopeProtocolMapper(ctx, token, targetRealm, scopeID, mapperID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return ProtocolMapperInfo{}, err
	}
	return mapScopeProtocolMapper(mapper), nil
}

func (s *service) GetDefaultDefaultClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error) {
	return s.fetchRealmClientScopes(ctx, realm, s.client.GetDefaultDefaultClientScopes)
}

func (s *service) GetDefaultOptionalClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error) {
	return s.fetchRealmClientScopes(ctx, realm, s.client.GetDefaultOptionalClientScopes)
}

func (s *service) GetClientScopeRealmRoles(ctx context.Context, realm, scopeID string) ([]RoleInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(scopeID); valErr != nil {
		return nil, valErr
	}
	roles, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Role, error) {
		res, callErr := s.client.GetClientScopesScopeMappingsRealmRoles(ctx, token, targetRealm, scopeID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapRoles(roles), nil
}

func (s *service) GetClientScopeClientRoles(ctx context.Context, realm, scopeID, clientUUID string) ([]RoleInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(scopeID); valErr != nil {
		return nil, valErr
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	roles, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Role, error) {
		res, callErr := s.client.GetClientScopesScopeMappingsClientRoles(ctx, token, targetRealm, scopeID, clientUUID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapRoles(roles), nil
}

func (s *service) fetchRealmClientScopes(
	ctx context.Context,
	realm string,
	fn func(context.Context, string, string) ([]*gocloak.ClientScope, error),
) ([]ClientScopeInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	scopes, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ClientScope, error) {
		res, callErr := fn(ctx, token, targetRealm)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapClientScopes(scopes), nil
}

func (s *service) fetchClientScopesForID(
	ctx context.Context,
	realm, clientUUID string,
	fn func(token, targetRealm string) ([]*gocloak.ClientScope, error),
) ([]ClientScopeInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	scopes, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ClientScope, error) {
		res, callErr := fn(token, targetRealm)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapClientScopes(scopes), nil
}

func (s *service) fetchClientSessionList(
	ctx context.Context,
	realm, clientUUID string,
	first, pageSize int,
	fn func(context.Context, string, string, string, ...gocloak.GetClientUserSessionsParams) ([]*gocloak.UserSessionRepresentation, error),
) ([]UserSession, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	sessions, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.UserSessionRepresentation, error) {
		res, callErr := fn(ctx, token, targetRealm, clientUUID, gocloak.GetClientUserSessionsParams{
			First: &first,
			Max:   &pageSize,
		})
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapUserSessions(sessions), nil
}

func (s *service) fetchClients(ctx context.Context, token, realm string, first, pageSize int, filter ClientFilter) ([]*gocloak.Client, error) {
	clients, err := s.client.GetClients(ctx, token, realm, gocloak.GetClientsParams{
		ClientID: optionalStringPtr(filter.ClientID),
		First:    &first,
		Max:      &pageSize,
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return clients, nil
}

func (s *service) fetchClient(ctx context.Context, token, realm, clientUUID string) (*gocloak.Client, error) {
	client, err := s.client.GetClient(ctx, token, realm, clientUUID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if client == nil {
		return nil, errKeycloakRequest
	}
	return client, nil
}

func (s *service) fetchClientServiceAccount(ctx context.Context, token, realm, clientUUID string) (*gocloak.User, error) {
	user, err := s.client.GetClientServiceAccount(ctx, token, realm, clientUUID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if user == nil {
		return nil, errKeycloakRequest
	}
	return user, nil
}

func (s *service) fetchClientRoles(ctx context.Context, token, realm, clientUUID string, first, pageSize int, search string) ([]*gocloak.Role, error) {
	brief := true
	roles, err := s.client.GetClientRoles(ctx, token, realm, clientUUID, gocloak.GetRoleParams{
		BriefRepresentation: &brief,
		First:               &first,
		Max:                 &pageSize,
		Search:              optionalStringPtr(search),
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return roles, nil
}

func (s *service) fetchClientScope(ctx context.Context, token, realm, scopeID string) (*gocloak.ClientScope, error) {
	scope, err := s.client.GetClientScope(ctx, token, realm, scopeID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if scope == nil {
		return nil, errKeycloakRequest
	}
	return scope, nil
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
	return ClientInfo{
		ID:                           derefString(client.ID),
		ClientID:                     derefString(client.ClientID),
		Name:                         derefString(client.Name),
		Description:                  derefString(client.Description),
		Protocol:                     derefString(client.Protocol),
		Enabled:                      derefBool(client.Enabled),
		Public:                       derefBool(client.PublicClient),
		BearerOnly:                   derefBool(client.BearerOnly),
		ConsentRequired:              derefBool(client.ConsentRequired),
		StandardFlowEnabled:          derefBool(client.StandardFlowEnabled),
		ImplicitFlowEnabled:          derefBool(client.ImplicitFlowEnabled),
		ServiceAccountsEnabled:       derefBool(client.ServiceAccountsEnabled),
		DirectAccessGrants:           derefBool(client.DirectAccessGrantsEnabled),
		AuthorizationServicesEnabled: derefBool(client.AuthorizationServicesEnabled),
		FullScopeAllowed:             derefBool(client.FullScopeAllowed),
		RootURL:                      derefString(client.RootURL),
		BaseURL:                      derefString(client.BaseURL),
		RedirectURIs:                 sanitizeStringSlice(client.RedirectURIs),
		WebOrigins:                   sanitizeStringSlice(client.WebOrigins),
	}
}

func mapClientScopes(scopes []*gocloak.ClientScope) []ClientScopeInfo {
	result := make([]ClientScopeInfo, 0, len(scopes))
	for _, scope := range scopes {
		if scope != nil {
			result = append(result, mapClientScope(scope))
		}
	}
	return result
}

func mapClientScope(scope *gocloak.ClientScope) ClientScopeInfo {
	return ClientScopeInfo{
		ID:          derefString(scope.ID),
		Name:        derefString(scope.Name),
		Description: derefString(scope.Description),
		Protocol:    derefString(scope.Protocol),
	}
}

func mapClientProtocolMappers(mappers []gocloak.ProtocolMapperRepresentation) []ProtocolMapperInfo {
	result := make([]ProtocolMapperInfo, 0, len(mappers))
	for i := range mappers {
		m := &mappers[i]
		result = append(result, ProtocolMapperInfo{
			ID:              derefString(m.ID),
			Name:            derefString(m.Name),
			Protocol:        derefString(m.Protocol),
			ProtocolMapper:  derefString(m.ProtocolMapper),
			ConsentRequired: derefBool(m.ConsentRequired),
			Config:          sanitizeConfigMap(m.Config),
		})
	}
	return result
}

func mapScopeProtocolMappers(mappers []*gocloak.ProtocolMappers) []ProtocolMapperInfo {
	result := make([]ProtocolMapperInfo, 0, len(mappers))
	for _, m := range mappers {
		if m != nil {
			result = append(result, mapScopeProtocolMapper(m))
		}
	}
	return result
}

func mapScopeProtocolMapper(m *gocloak.ProtocolMappers) ProtocolMapperInfo {
	return ProtocolMapperInfo{
		ID:              derefString(m.ID),
		Name:            derefString(m.Name),
		Protocol:        derefString(m.Protocol),
		ProtocolMapper:  derefString(m.ProtocolMapper),
		ConsentRequired: derefBool(m.ConsentRequired),
		Config:          extractSafeProtocolMapperConfig(&m.ProtocolMappersConfig),
	}
}

func extractSafeProtocolMapperConfig(c *gocloak.ProtocolMappersConfig) map[string]string {
	entries := []struct {
		key string
		val *string
	}{
		{"claim.name", c.ClaimName},
		{"claim.value", c.ClaimValue},
		{"user.attribute", c.UserAttribute},
		{"jsonType.label", c.JSONTypeLabel},
		{"id.token.claim", c.IDTokenClaim},
		{"access.token.claim", c.AccessTokenClaim},
		{"userinfo.token.claim", c.UserinfoTokenClaim},
		{"introspection.token.claim", c.IntrospectionTokenClaim},
		{"multivalued", c.Multivalued},
		{"included.client.audience", c.IncludedClientAudience},
		{"included.custom.audience", c.IncludedCustomAudience},
		{"full.path", c.FullPath},
		{"attribute.name", c.AttributeName},
		{"attribute.nameformat", c.AttributeNameFormat},
		{"addOrganizationId", c.AddOrganizationID},
		{"addOrganizationAttributes", c.AddOrganizationAttributes},
	}
	cfg := make(map[string]string)
	for _, entry := range entries {
		if entry.val != nil && *entry.val != "" {
			cfg[entry.key] = sanitizeOutputString(*entry.val)
		}
	}
	if len(cfg) == 0 {
		return nil
	}
	return cfg
}
