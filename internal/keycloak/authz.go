package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v15"
)

func (s *service) GetResourceServer(ctx context.Context, realm, clientUUID string) (ResourceServerInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return ResourceServerInfo{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return ResourceServerInfo{}, valErr
	}
	rs, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.ResourceServerRepresentation, error) {
		res, callErr := s.client.GetResourceServer(ctx, token, targetRealm, clientUUID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return ResourceServerInfo{}, err
	}
	return ResourceServerInfo{
		ID:                            derefString(rs.ID),
		ClientID:                      derefString(rs.ClientID),
		Name:                          derefString(rs.Name),
		AllowRemoteResourceManagement: derefBool(rs.AllowRemoteResourceManagement),
		PolicyEnforcementMode:         sanitizeOutputString(string(rs.PolicyEnforcementMode)),
		DecisionStrategy:              sanitizeOutputString(string(rs.DecisionStrategy)),
	}, nil
}

func (s *service) ListAuthzResources(ctx context.Context, realm, clientUUID string, first, pageSize int, filter *AuthzResourceFilter) ([]AuthzResourceInfo, error) {
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
	params := gocloak.GetResourceParams{First: &first, Max: &pageSize}
	if filter != nil {
		for _, v := range [...]string{filter.Name, filter.Owner, filter.Type, filter.URI, filter.Scope} {
			if valErr := validateFilterString(v); valErr != nil {
				return nil, valErr
			}
		}
		params.Name = optionalStringPtr(filter.Name)
		params.Owner = optionalStringPtr(filter.Owner)
		params.Type = optionalStringPtr(filter.Type)
		params.URI = optionalStringPtr(filter.URI)
		params.Scope = optionalStringPtr(filter.Scope)
	}
	resources, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ResourceRepresentation, error) {
		res, callErr := s.client.GetResources(ctx, token, targetRealm, clientUUID, params)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapAuthzResources(resources), nil
}

func (s *service) GetAuthzResource(ctx context.Context, realm, clientUUID, resourceID string) (AuthzResourceInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return AuthzResourceInfo{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return AuthzResourceInfo{}, valErr
	}
	if valErr := validateIdentifier(resourceID); valErr != nil {
		return AuthzResourceInfo{}, valErr
	}
	resource, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.ResourceRepresentation, error) {
		res, callErr := s.client.GetResource(ctx, token, targetRealm, clientUUID, resourceID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return AuthzResourceInfo{}, err
	}
	return mapAuthzResource(resource), nil
}

func (s *service) ListAuthzScopes(ctx context.Context, realm, clientUUID string, first, pageSize int, name string) ([]AuthzScopeInfo, error) {
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
	if valErr := validateFilterString(name); valErr != nil {
		return nil, valErr
	}
	scopes, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ScopeRepresentation, error) {
		res, callErr := s.client.GetScopes(ctx, token, targetRealm, clientUUID, gocloak.GetScopeParams{
			First: &first,
			Max:   &pageSize,
			Name:  optionalStringPtr(name),
		})
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapAuthzScopes(scopes), nil
}

func (s *service) GetAuthzScope(ctx context.Context, realm, clientUUID, scopeID string) (AuthzScopeInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return AuthzScopeInfo{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return AuthzScopeInfo{}, valErr
	}
	if valErr := validateIdentifier(scopeID); valErr != nil {
		return AuthzScopeInfo{}, valErr
	}
	scope, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.ScopeRepresentation, error) {
		res, callErr := s.client.GetScope(ctx, token, targetRealm, clientUUID, scopeID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return AuthzScopeInfo{}, err
	}
	return mapAuthzScope(scope), nil
}

func (s *service) ListAuthzPolicies(ctx context.Context, realm, clientUUID string, first, pageSize int, filter AuthzPolicyFilter) ([]AuthzPolicyInfo, error) {
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
	for _, v := range [...]string{filter.Name, filter.Type} {
		if valErr := validateFilterString(v); valErr != nil {
			return nil, valErr
		}
	}
	policies, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.PolicyRepresentation, error) {
		res, callErr := s.client.GetPolicies(ctx, token, targetRealm, clientUUID, gocloak.GetPolicyParams{
			First: &first,
			Max:   &pageSize,
			Name:  optionalStringPtr(filter.Name),
			Type:  optionalStringPtr(filter.Type),
		})
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapAuthzPolicies(policies), nil
}

func (s *service) GetAuthzPolicy(ctx context.Context, realm, clientUUID, policyID string) (AuthzPolicyInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return AuthzPolicyInfo{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return AuthzPolicyInfo{}, valErr
	}
	if valErr := validateIdentifier(policyID); valErr != nil {
		return AuthzPolicyInfo{}, valErr
	}
	policy, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.PolicyRepresentation, error) {
		res, callErr := s.client.GetPolicy(ctx, token, targetRealm, clientUUID, policyID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return AuthzPolicyInfo{}, err
	}
	return mapAuthzPolicy(policy), nil
}

func (s *service) ListAuthzPermissions(ctx context.Context, realm, clientUUID string, first, pageSize int, filter AuthzPermissionFilter) ([]AuthzPermissionInfo, error) {
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
	for _, v := range [...]string{filter.Name, filter.Resource, filter.Scope, filter.Type} {
		if valErr := validateFilterString(v); valErr != nil {
			return nil, valErr
		}
	}
	perms, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.PermissionRepresentation, error) {
		res, callErr := s.client.GetPermissions(ctx, token, targetRealm, clientUUID, gocloak.GetPermissionParams{
			First:    &first,
			Max:      &pageSize,
			Name:     optionalStringPtr(filter.Name),
			Resource: optionalStringPtr(filter.Resource),
			Scope:    optionalStringPtr(filter.Scope),
			Type:     optionalStringPtr(filter.Type),
		})
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapAuthzPermissions(perms), nil
}

func (s *service) GetAuthzPermission(ctx context.Context, realm, clientUUID, permissionID string) (AuthzPermissionInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return AuthzPermissionInfo{}, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return AuthzPermissionInfo{}, valErr
	}
	if valErr := validateIdentifier(permissionID); valErr != nil {
		return AuthzPermissionInfo{}, valErr
	}
	perm, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.PermissionRepresentation, error) {
		res, callErr := s.client.GetPermission(ctx, token, targetRealm, clientUUID, permissionID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return AuthzPermissionInfo{}, err
	}
	return mapAuthzPermission(perm), nil
}

func (s *service) GetPolicyAssociatedPolicies(ctx context.Context, realm, clientUUID, policyID string) ([]AuthzPolicyInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	if valErr := validateIdentifier(policyID); valErr != nil {
		return nil, valErr
	}
	policies, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.PolicyRepresentation, error) {
		res, callErr := s.client.GetAuthorizationPolicyAssociatedPolicies(ctx, token, targetRealm, clientUUID, policyID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapAuthzPolicies(policies), nil
}

func (s *service) GetPolicyResources(ctx context.Context, realm, clientUUID, policyID string) ([]NamedRef, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	if valErr := validateIdentifier(policyID); valErr != nil {
		return nil, valErr
	}
	resources, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.PolicyResourceRepresentation, error) {
		res, callErr := s.client.GetAuthorizationPolicyResources(ctx, token, targetRealm, clientUUID, policyID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]NamedRef, 0, len(resources))
	for _, r := range resources {
		if r != nil {
			result = append(result, NamedRef{ID: sanitizeOutputString(r.ID), Name: sanitizeOutputString(r.Name)})
		}
	}
	return result, nil
}

func (s *service) GetPolicyScopes(ctx context.Context, realm, clientUUID, policyID string) ([]NamedRef, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(clientUUID); valErr != nil {
		return nil, valErr
	}
	if valErr := validateIdentifier(policyID); valErr != nil {
		return nil, valErr
	}
	scopes, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.PolicyScopeRepresentation, error) {
		res, callErr := s.client.GetAuthorizationPolicyScopes(ctx, token, targetRealm, clientUUID, policyID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]NamedRef, 0, len(scopes))
	for _, sc := range scopes {
		if sc != nil {
			result = append(result, NamedRef{ID: sanitizeOutputString(sc.ID), Name: sanitizeOutputString(sc.Name)})
		}
	}
	return result, nil
}

func mapAuthzResources(resources []*gocloak.ResourceRepresentation) []AuthzResourceInfo {
	result := make([]AuthzResourceInfo, 0, len(resources))
	for _, r := range resources {
		if r != nil {
			result = append(result, mapAuthzResource(r))
		}
	}
	return result
}

func mapAuthzResource(r *gocloak.ResourceRepresentation) AuthzResourceInfo {
	scopes := make([]string, 0, len(r.Scopes)+len(r.ResourceScopes))
	for i := range r.Scopes {
		if name := derefString(r.Scopes[i].Name); name != "" {
			scopes = append(scopes, name)
		}
	}
	for i := range r.ResourceScopes {
		if name := derefString(r.ResourceScopes[i].Name); name != "" {
			scopes = append(scopes, name)
		}
	}
	return AuthzResourceInfo{
		ID:                 derefString(r.ID),
		Name:               derefString(r.Name),
		DisplayName:        derefString(r.DisplayName),
		Type:               derefString(r.Type),
		IconURI:            derefString(r.IconURI),
		OwnerManagedAccess: derefBool(r.OwnerManagedAccess),
		URIs:               sanitizeStringSlice(r.URIs),
		Scopes:             scopes,
	}
}

func mapAuthzScopes(scopes []*gocloak.ScopeRepresentation) []AuthzScopeInfo {
	result := make([]AuthzScopeInfo, 0, len(scopes))
	for _, sc := range scopes {
		if sc != nil {
			result = append(result, mapAuthzScope(sc))
		}
	}
	return result
}

func mapAuthzScope(sc *gocloak.ScopeRepresentation) AuthzScopeInfo {
	return AuthzScopeInfo{
		ID:          derefString(sc.ID),
		Name:        derefString(sc.Name),
		DisplayName: derefString(sc.DisplayName),
		IconURI:     derefString(sc.IconURI),
	}
}

func mapAuthzPolicies(policies []*gocloak.PolicyRepresentation) []AuthzPolicyInfo {
	result := make([]AuthzPolicyInfo, 0, len(policies))
	for _, p := range policies {
		if p != nil {
			result = append(result, mapAuthzPolicy(p))
		}
	}
	return result
}

func mapAuthzPolicy(p *gocloak.PolicyRepresentation) AuthzPolicyInfo {
	return AuthzPolicyInfo{
		ID:               derefString(p.ID),
		Name:             derefString(p.Name),
		Description:      derefString(p.Description),
		Type:             derefString(p.Type),
		Logic:            sanitizeOutputString(string(p.Logic)),
		DecisionStrategy: sanitizeOutputString(string(p.DecisionStrategy)),
		Resources:        sanitizeStringSlice(p.Resources),
		Scopes:           sanitizeStringSlice(p.Scopes),
		Policies:         sanitizeStringSlice(p.Policies),
	}
}

func mapAuthzPermissions(perms []*gocloak.PermissionRepresentation) []AuthzPermissionInfo {
	result := make([]AuthzPermissionInfo, 0, len(perms))
	for _, p := range perms {
		if p != nil {
			result = append(result, mapAuthzPermission(p))
		}
	}
	return result
}

func mapAuthzPermission(p *gocloak.PermissionRepresentation) AuthzPermissionInfo {
	return AuthzPermissionInfo{
		ID:               derefString(p.ID),
		Name:             derefString(p.Name),
		Description:      derefString(p.Description),
		Type:             derefString(p.Type),
		ResourceType:     derefString(p.ResourceType),
		Logic:            sanitizeOutputString(string(p.Logic)),
		DecisionStrategy: sanitizeOutputString(string(p.DecisionStrategy)),
		Resources:        sanitizeStringSlice(p.Resources),
		Scopes:           sanitizeStringSlice(p.Scopes),
		Policies:         sanitizeStringSlice(p.Policies),
	}
}
