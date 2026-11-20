package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

func (s *service) ListRealmRoles(ctx context.Context, realm string, first, pageSize int, search string) ([]RoleInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err = validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	if err = validateFilterString(search); err != nil {
		return nil, err
	}
	roles, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Role, error) {
		return s.fetchRealmRoles(ctx, token, targetRealm, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapRoles(roles), nil
}

func (s *service) GetRealmRole(ctx context.Context, realm, roleName string) (RoleInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RoleInfo{}, err
	}
	if err = validateIdentifier(roleName); err != nil {
		return RoleInfo{}, err
	}
	role, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.Role, error) {
		return s.fetchRealmRole(ctx, token, targetRealm, roleName)
	})
	if err != nil {
		return RoleInfo{}, err
	}
	return mapRole(role), nil
}

func (s *service) GetUsersInRole(ctx context.Context, realm, roleName string, first, pageSize int) ([]User, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err = validateIdentifier(roleName); err != nil {
		return nil, err
	}
	if err = validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	users, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.User, error) {
		return s.fetchUsersByRole(ctx, token, targetRealm, roleName, first, pageSize)
	})
	if err != nil {
		return nil, err
	}
	return mapUsers(users), nil
}

func (s *service) GetUsersInClientRole(ctx context.Context, realm, clientUUID, roleName string, first, pageSize int) ([]User, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err = validateIdentifier(clientUUID); err != nil {
		return nil, err
	}
	if err = validateIdentifier(roleName); err != nil {
		return nil, err
	}
	if err = validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	users, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.User, error) {
		return s.fetchUsersByClientRole(ctx, token, targetRealm, clientUUID, roleName, first, pageSize)
	})
	if err != nil {
		return nil, err
	}
	return mapUsers(users), nil
}

func (s *service) fetchRealmRoles(ctx context.Context, token, realm string, first, pageSize int, search string) ([]*gocloak.Role, error) {
	brief := true
	roles, err := s.client.GetRealmRoles(ctx, token, realm, gocloak.GetRoleParams{
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

func (s *service) fetchRealmRole(ctx context.Context, token, realm, roleName string) (*gocloak.Role, error) {
	role, err := s.client.GetRealmRole(ctx, token, realm, roleName)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if role == nil {
		return nil, errKeycloakRequest
	}
	return role, nil
}

func (s *service) fetchUsersByRole(ctx context.Context, token, realm, roleName string, first, pageSize int) ([]*gocloak.User, error) {
	users, err := s.client.GetUsersByRoleName(ctx, token, realm, roleName, gocloak.GetUsersByRoleParams{
		First: &first,
		Max:   &pageSize,
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return users, nil
}

func (s *service) fetchUsersByClientRole(ctx context.Context, token, realm, clientUUID, roleName string, first, pageSize int) ([]*gocloak.User, error) {
	users, err := s.client.GetUsersByClientRoleName(ctx, token, realm, clientUUID, roleName, gocloak.GetUsersByRoleParams{
		First: &first,
		Max:   &pageSize,
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return users, nil
}

func mapRoles(roles []*gocloak.Role) []RoleInfo {
	result := make([]RoleInfo, 0, len(roles))
	for _, role := range roles {
		if role != nil {
			result = append(result, mapRole(role))
		}
	}
	return result
}

func mapRoleValues(roles []gocloak.Role) []RoleInfo {
	result := make([]RoleInfo, 0, len(roles))
	for i := range roles {
		result = append(result, mapRole(&roles[i]))
	}
	return result
}

func mapRole(role *gocloak.Role) RoleInfo {
	return RoleInfo{
		ID:          derefString(role.ID),
		Name:        derefString(role.Name),
		Description: derefString(role.Description),
		Composite:   derefBool(role.Composite),
		ClientRole:  derefBool(role.ClientRole),
		ContainerID: derefString(role.ContainerID),
	}
}

func mapRoleMappings(mappings *gocloak.MappingsRepresentation) RoleMappings {
	result := RoleMappings{RealmRoles: []RoleInfo{}}
	if mappings == nil {
		return result
	}
	result.RealmRoles = mapRoleValues(mappings.RealmMappings)
	if len(mappings.ClientMappings) == 0 {
		return result
	}
	result.ClientRoles = make(map[string][]RoleInfo, len(mappings.ClientMappings))
	for clientName, mapping := range mappings.ClientMappings {
		if mapping != nil {
			result.ClientRoles[clientName] = mapRoleValues(mapping.Mappings)
		}
	}
	return result
}
