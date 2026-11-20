package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

func (s *service) ListGroups(ctx context.Context, realm string, first, pageSize int, search string) ([]GroupInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err := validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	if err := validateFilterString(search); err != nil {
		return nil, err
	}
	groups, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Group, error) {
		return s.fetchGroups(ctx, token, targetRealm, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapGroups(groups), nil
}

func (s *service) CountGroups(ctx context.Context, realm, search string) (int, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return 0, err
	}
	if err := validateFilterString(search); err != nil {
		return 0, err
	}
	return runWithTokenRetry(ctx, s.tokens, func(token string) (int, error) {
		return s.fetchGroupsCount(ctx, token, targetRealm, search)
	})
}

func (s *service) GetGroup(ctx context.Context, realm, groupID string) (GroupInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return GroupInfo{}, err
	}
	if err := validateIdentifier(groupID); err != nil {
		return GroupInfo{}, err
	}
	group, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.Group, error) {
		return s.fetchGroup(ctx, token, targetRealm, groupID)
	})
	if err != nil {
		return GroupInfo{}, err
	}
	return mapGroup(group), nil
}

func (s *service) GetGroupMembers(ctx context.Context, realm, groupID string, first, pageSize int) ([]User, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err := validateIdentifier(groupID); err != nil {
		return nil, err
	}
	if err := validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	users, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.User, error) {
		return s.fetchGroupMembers(ctx, token, targetRealm, groupID, first, pageSize)
	})
	if err != nil {
		return nil, err
	}
	return mapUsers(users), nil
}

func (s *service) GetGroupRoles(ctx context.Context, realm, groupID string) (RoleMappings, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RoleMappings{}, err
	}
	if err := validateIdentifier(groupID); err != nil {
		return RoleMappings{}, err
	}
	mappings, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.MappingsRepresentation, error) {
		return s.fetchGroupRoleMappings(ctx, token, targetRealm, groupID)
	})
	if err != nil {
		return RoleMappings{}, err
	}
	return mapRoleMappings(mappings), nil
}

func (s *service) fetchGroups(ctx context.Context, token, realm string, first, pageSize int, search string) ([]*gocloak.Group, error) {
	brief := true
	groups, err := s.client.GetGroups(ctx, token, realm, gocloak.GetGroupsParams{
		BriefRepresentation: &brief,
		First:               &first,
		Max:                 &pageSize,
		Search:              optionalStringPtr(search),
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return groups, nil
}

func (s *service) fetchGroupsCount(ctx context.Context, token, realm, search string) (int, error) {
	count, err := s.client.GetGroupsCount(ctx, token, realm, gocloak.GetGroupsParams{
		Search: optionalStringPtr(search),
	})
	if err != nil {
		return 0, classifyUpstreamError(err)
	}
	return count, nil
}

func (s *service) fetchGroup(ctx context.Context, token, realm, groupID string) (*gocloak.Group, error) {
	group, err := s.client.GetGroup(ctx, token, realm, groupID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if group == nil {
		return nil, errKeycloakRequest
	}
	return group, nil
}

func (s *service) fetchGroupMembers(ctx context.Context, token, realm, groupID string, first, pageSize int) ([]*gocloak.User, error) {
	brief := true
	users, err := s.client.GetGroupMembers(ctx, token, realm, groupID, gocloak.GetGroupsParams{
		BriefRepresentation: &brief,
		First:               &first,
		Max:                 &pageSize,
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return users, nil
}

func (s *service) fetchGroupRoleMappings(ctx context.Context, token, realm, groupID string) (*gocloak.MappingsRepresentation, error) {
	mappings, err := s.client.GetRoleMappingByGroupID(ctx, token, realm, groupID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return mappings, nil
}

func mapGroups(groups []*gocloak.Group) []GroupInfo {
	result := make([]GroupInfo, 0, len(groups))
	for _, group := range groups {
		if group != nil {
			result = append(result, mapGroup(group))
		}
	}
	return result
}

func mapGroup(group *gocloak.Group) GroupInfo {
	return GroupInfo{
		ID:   derefString(group.ID),
		Name: derefString(group.Name),
		Path: derefString(group.Path),
	}
}
