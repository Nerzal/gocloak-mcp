package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v15"
)

func (s *service) ListOrganizations(ctx context.Context, realm string, first, pageSize int, search string) ([]OrganizationInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	if valErr := validateFilterString(search); valErr != nil {
		return nil, valErr
	}
	orgs, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.OrganizationRepresentation, error) {
		return s.fetchOrganizations(ctx, token, targetRealm, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapOrganizations(orgs), nil
}

func (s *service) GetOrganization(ctx context.Context, realm, orgID string) (OrganizationInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return OrganizationInfo{}, err
	}
	if valErr := validateIdentifier(orgID); valErr != nil {
		return OrganizationInfo{}, valErr
	}
	org, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.OrganizationRepresentation, error) {
		res, callErr := s.client.GetOrganizationByID(ctx, token, targetRealm, orgID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return OrganizationInfo{}, err
	}
	return mapOrganization(org), nil
}

func (s *service) CountOrganizations(ctx context.Context, realm, search string) (int64, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return 0, err
	}
	if valErr := validateFilterString(search); valErr != nil {
		return 0, valErr
	}
	return runWithTokenRetry(ctx, s.tokens, func(token string) (int64, error) {
		count, callErr := s.client.GetOrganizationCount(ctx, token, targetRealm, gocloak.GetOrganizationCountParams{
			Search: optionalStringPtr(search),
		})
		if callErr != nil {
			return 0, classifyUpstreamError(callErr)
		}
		return count, nil
	})
}

func (s *service) GetOrganizationMembers(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]OrganizationMember, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(orgID); valErr != nil {
		return nil, valErr
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	if valErr := validateFilterString(search); valErr != nil {
		return nil, valErr
	}
	members, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.MemberRepresentation, error) {
		return s.fetchOrganizationMembers(ctx, token, targetRealm, orgID, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapOrganizationMembers(members), nil
}

func (s *service) CountOrganizationMembers(ctx context.Context, realm, orgID string) (int, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return 0, err
	}
	if valErr := validateIdentifier(orgID); valErr != nil {
		return 0, valErr
	}
	return runWithTokenRetry(ctx, s.tokens, func(token string) (int, error) {
		count, callErr := s.client.GetOrganizationMemberCount(ctx, token, targetRealm, orgID)
		if callErr != nil {
			return 0, classifyUpstreamError(callErr)
		}
		return count, nil
	})
}

func (s *service) GetOrganizationMember(ctx context.Context, realm, orgID, userID string) (OrganizationMember, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return OrganizationMember{}, err
	}
	if valErr := validateIdentifier(orgID); valErr != nil {
		return OrganizationMember{}, valErr
	}
	if valErr := validateIdentifier(userID); valErr != nil {
		return OrganizationMember{}, valErr
	}
	member, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.MemberRepresentation, error) {
		res, callErr := s.client.GetOrganizationMemberByID(ctx, token, targetRealm, orgID, userID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return OrganizationMember{}, err
	}
	return mapOrganizationMember(member), nil
}

func (s *service) GetUserOrganizations(ctx context.Context, realm, userID string) ([]OrganizationInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(userID); valErr != nil {
		return nil, valErr
	}
	orgs, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.OrganizationRepresentation, error) {
		res, callErr := s.client.GetMemberAssociatedOrganizations(ctx, token, targetRealm, userID, true)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapOrganizations(orgs), nil
}

func (s *service) ListOrganizationIdentityProviders(ctx context.Context, realm, orgID string) ([]IdentityProviderInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(orgID); valErr != nil {
		return nil, valErr
	}
	idps, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.IdentityProviderRepresentation, error) {
		res, callErr := s.client.GetOrganizationIdentityProviders(ctx, token, targetRealm, orgID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapIdentityProviders(idps), nil
}

func (s *service) ListOrganizationInvitations(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]OrganizationInvitationInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(orgID); valErr != nil {
		return nil, valErr
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	if valErr := validateFilterString(search); valErr != nil {
		return nil, valErr
	}
	invitations, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.OrganizationInvitationRepresentation, error) {
		res, callErr := s.client.GetOrganizationInvitations(ctx, token, targetRealm, orgID, gocloak.GetOrganizationInvitationsParams{
			First:  &first,
			Max:    &pageSize,
			Search: optionalStringPtr(search),
		})
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapOrganizationInvitations(invitations), nil
}

func (s *service) ListOrganizationGroups(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]GroupInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(orgID); valErr != nil {
		return nil, valErr
	}
	if valErr := validatePagination(first, pageSize); valErr != nil {
		return nil, valErr
	}
	if valErr := validateFilterString(search); valErr != nil {
		return nil, valErr
	}
	brief := true
	groups, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Group, error) {
		res, callErr := s.client.GetOrganizationGroups(ctx, token, targetRealm, orgID, gocloak.GetOrganizationGroupsParams{
			BriefRepresentation: &brief,
			First:               &first,
			Max:                 &pageSize,
			Search:              optionalStringPtr(search),
		})
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return mapGroups(groups), nil
}

func (s *service) fetchOrganizations(ctx context.Context, token, realm string, first, pageSize int, search string) ([]*gocloak.OrganizationRepresentation, error) {
	brief := true
	orgs, err := s.client.GetOrganizations(ctx, token, realm, gocloak.GetOrganizationsParams{
		BriefRepresentation: &brief,
		First:               &first,
		Max:                 &pageSize,
		Search:              optionalStringPtr(search),
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return orgs, nil
}

func (s *service) fetchOrganizationMembers(ctx context.Context, token, realm, orgID string, first, pageSize int, search string) ([]*gocloak.MemberRepresentation, error) {
	members, err := s.client.GetOrganizationMembers(ctx, token, realm, orgID, gocloak.GetMembersParams{
		First:  &first,
		Max:    &pageSize,
		Search: optionalStringPtr(search),
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return members, nil
}

func mapOrganizations(orgs []*gocloak.OrganizationRepresentation) []OrganizationInfo {
	result := make([]OrganizationInfo, 0, len(orgs))
	for _, org := range orgs {
		if org != nil {
			result = append(result, mapOrganization(org))
		}
	}
	return result
}

func mapOrganization(org *gocloak.OrganizationRepresentation) OrganizationInfo {
	domains := make([]string, 0, len(org.Domains))
	for _, d := range org.Domains {
		if d.Name != nil && *d.Name != "" {
			domains = append(domains, sanitizeOutputString(*d.Name))
		}
	}
	return OrganizationInfo{
		ID:          derefString(org.ID),
		Name:        derefString(org.Name),
		Alias:       derefString(org.Alias),
		Description: derefString(org.Description),
		Enabled:     derefBool(org.Enabled),
		Domains:     domains,
	}
}

func mapOrganizationMembers(members []*gocloak.MemberRepresentation) []OrganizationMember {
	result := make([]OrganizationMember, 0, len(members))
	for _, member := range members {
		if member != nil {
			result = append(result, mapOrganizationMember(member))
		}
	}
	return result
}

func mapOrganizationMember(member *gocloak.MemberRepresentation) OrganizationMember {
	return OrganizationMember{
		User:           mapUser(&member.User),
		MembershipType: sanitizeOutputString(string(member.MembershipType)),
	}
}

func mapOrganizationInvitations(invitations []*gocloak.OrganizationInvitationRepresentation) []OrganizationInvitationInfo {
	result := make([]OrganizationInvitationInfo, 0, len(invitations))
	for _, inv := range invitations {
		if inv == nil {
			continue
		}
		result = append(result, OrganizationInvitationInfo{
			ID:             sanitizeOutputString(inv.ID),
			OrganizationID: sanitizeOutputString(inv.OrganizationID),
			Email:          sanitizeOutputString(inv.Email),
			FirstName:      sanitizeOutputString(inv.FirstName),
			LastName:       sanitizeOutputString(inv.LastName),
			SentDate:       inv.SentDate,
			ExpiresAt:      inv.ExpiresAt,
			Status:         sanitizeOutputString(string(inv.Status)),
		})
	}
	return result
}
