package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

func (s *service) ListClients(ctx context.Context, realm string, first, pageSize int, filter ClientFilter) ([]ClientInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err = validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	if err = validateFilterString(filter.ClientID); err != nil {
		return nil, err
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
	if err = validateIdentifier(clientUUID); err != nil {
		return ClientInfo{}, err
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
	if err = validateIdentifier(clientUUID); err != nil {
		return User{}, err
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
	if err = validateIdentifier(clientUUID); err != nil {
		return nil, err
	}
	if err = validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	if err = validateFilterString(search); err != nil {
		return nil, err
	}
	roles, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Role, error) {
		return s.fetchClientRoles(ctx, token, targetRealm, clientUUID, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapRoles(roles), nil
}

func (s *service) ListClientScopes(ctx context.Context, realm string) ([]ClientScopeInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	scopes, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ClientScope, error) {
		return s.fetchClientScopes(ctx, token, targetRealm)
	})
	if err != nil {
		return nil, err
	}
	return mapClientScopes(scopes), nil
}

func (s *service) GetClientScope(ctx context.Context, realm, scopeID string) (ClientScopeInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return ClientScopeInfo{}, err
	}
	if err = validateIdentifier(scopeID); err != nil {
		return ClientScopeInfo{}, err
	}
	scope, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.ClientScope, error) {
		return s.fetchClientScope(ctx, token, targetRealm, scopeID)
	})
	if err != nil {
		return ClientScopeInfo{}, err
	}
	return mapClientScope(scope), nil
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

func (s *service) fetchClientScopes(ctx context.Context, token, realm string) ([]*gocloak.ClientScope, error) {
	scopes, err := s.client.GetClientScopes(ctx, token, realm)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return scopes, nil
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
		ID:                     derefString(client.ID),
		ClientID:               derefString(client.ClientID),
		Name:                   derefString(client.Name),
		Description:            derefString(client.Description),
		Protocol:               derefString(client.Protocol),
		Enabled:                derefBool(client.Enabled),
		Public:                 derefBool(client.PublicClient),
		StandardFlowEnabled:    derefBool(client.StandardFlowEnabled),
		ServiceAccountsEnabled: derefBool(client.ServiceAccountsEnabled),
		DirectAccessGrants:     derefBool(client.DirectAccessGrantsEnabled),
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
