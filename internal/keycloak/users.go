package keycloak

import (
	"context"
	"maps"

	"github.com/Nerzal/gocloak/v15"
)

func (s *service) ListUsers(ctx context.Context, realm string, first, pageSize int, filter UserFilter) ([]User, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	if valErr := validateUserFilter(filter); valErr != nil {
		return nil, valErr
	}
	users, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.User, error) {
		return s.fetchUsers(ctx, token, targetRealm, first, pageSize, filter)
	})
	if err != nil {
		return nil, err
	}
	return mapUsers(users), nil
}

func (s *service) GetUser(ctx context.Context, realm, userID string) (User, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return User{}, err
	}
	if valErr := validateIdentifier(userID); valErr != nil {
		return User{}, valErr
	}
	user, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.User, error) {
		return s.fetchUser(ctx, token, targetRealm, userID)
	})
	if err != nil {
		return User{}, err
	}
	return mapUser(user), nil
}

func (s *service) CountUsers(ctx context.Context, realm string, filter UserFilter) (int, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return 0, err
	}
	if valErr := validateUserFilter(filter); valErr != nil {
		return 0, valErr
	}
	return runWithTokenRetry(ctx, s.tokens, func(token string) (int, error) {
		return s.fetchUserCount(ctx, token, targetRealm, filter)
	})
}

func (s *service) GetUserSessions(ctx context.Context, realm, userID string) ([]UserSession, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(userID); valErr != nil {
		return nil, valErr
	}
	sessions, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.UserSessionRepresentation, error) {
		return s.fetchUserSessions(ctx, token, targetRealm, userID)
	})
	if err != nil {
		return nil, err
	}
	return mapUserSessions(sessions), nil
}

func (s *service) GetUserGroups(ctx context.Context, realm, userID string, first, pageSize int) ([]GroupInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(userID); valErr != nil {
		return nil, valErr
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	groups, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Group, error) {
		return s.fetchUserGroups(ctx, token, targetRealm, userID, first, pageSize)
	})
	if err != nil {
		return nil, err
	}
	return mapGroups(groups), nil
}

func (s *service) GetUserRoles(ctx context.Context, realm, userID string) (RoleMappings, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RoleMappings{}, err
	}
	if valErr := validateIdentifier(userID); valErr != nil {
		return RoleMappings{}, valErr
	}
	mappings, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.MappingsRepresentation, error) {
		return s.fetchUserRoleMappings(ctx, token, targetRealm, userID)
	})
	if err != nil {
		return RoleMappings{}, err
	}
	return mapRoleMappings(mappings), nil
}

func validateUserFilter(filter UserFilter) error {
	for _, value := range [...]string{filter.Search, filter.Username, filter.Email} {
		if err := validateFilterString(value); err != nil {
			return err
		}
	}
	return nil
}

func buildUserParams(first, pageSize int, filter UserFilter, withPage bool) gocloak.GetUsersParams {
	brief := true
	params := gocloak.GetUsersParams{
		BriefRepresentation: &brief,
		Search:              optionalStringPtr(filter.Search),
		Username:            optionalStringPtr(filter.Username),
		Email:               optionalStringPtr(filter.Email),
	}
	if filter.Exact {
		exact := true
		params.Exact = &exact
	}
	if withPage {
		params.First = &first
		params.Max = &pageSize
	}
	return params
}

func (s *service) fetchUsers(ctx context.Context, token, realm string, first, pageSize int, filter UserFilter) ([]*gocloak.User, error) {
	users, err := s.client.GetUsers(ctx, token, realm, buildUserParams(first, pageSize, filter, true))
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return users, nil
}

func (s *service) fetchUser(ctx context.Context, token, realm, userID string) (*gocloak.User, error) {
	user, err := s.client.GetUserByID(ctx, token, realm, userID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if user == nil {
		return nil, errKeycloakRequest
	}
	return user, nil
}

func (s *service) fetchUserCount(ctx context.Context, token, realm string, filter UserFilter) (int, error) {
	count, err := s.client.GetUserCount(ctx, token, realm, buildUserParams(0, 0, filter, false))
	if err != nil {
		return 0, classifyUpstreamError(err)
	}
	return count, nil
}

func (s *service) fetchUserSessions(ctx context.Context, token, realm, userID string) ([]*gocloak.UserSessionRepresentation, error) {
	sessions, err := s.client.GetUserSessions(ctx, token, realm, userID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return sessions, nil
}

func (s *service) fetchUserGroups(ctx context.Context, token, realm, userID string, first, pageSize int) ([]*gocloak.Group, error) {
	brief := true
	groups, err := s.client.GetUserGroups(ctx, token, realm, userID, gocloak.GetGroupsParams{
		BriefRepresentation: &brief,
		First:               &first,
		Max:                 &pageSize,
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return groups, nil
}

func (s *service) fetchUserRoleMappings(ctx context.Context, token, realm, userID string) (*gocloak.MappingsRepresentation, error) {
	mappings, err := s.client.GetRoleMappingByUserID(ctx, token, realm, userID)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return mappings, nil
}

func mapUsers(users []*gocloak.User) []User {
	result := make([]User, 0, len(users))
	for _, user := range users {
		if user != nil {
			result = append(result, mapUser(user))
		}
	}
	return result
}

func mapUser(user *gocloak.User) User {
	return User{
		ID:            derefString(user.ID),
		Username:      derefString(user.Username),
		Email:         derefString(user.Email),
		FirstName:     derefString(user.FirstName),
		LastName:      derefString(user.LastName),
		Enabled:       derefBool(user.Enabled),
		EmailVerified: derefBool(user.EmailVerified),
	}
}

func mapUserSessions(sessions []*gocloak.UserSessionRepresentation) []UserSession {
	result := make([]UserSession, 0, len(sessions))
	for _, session := range sessions {
		if session == nil {
			continue
		}
		var clients map[string]string
		if len(session.Clients) > 0 {
			clients = maps.Clone(session.Clients)
		}
		result = append(result, UserSession{
			ID:         sanitizeOutputString(session.ID, maxOutputFieldLen),
			UserID:     sanitizeOutputString(session.UserID, maxOutputFieldLen),
			Username:   sanitizeOutputString(session.Username, maxOutputFieldLen),
			Start:      session.Start,
			LastAccess: session.LastAccess,
			Clients:    clients,
		})
	}
	return result
}
