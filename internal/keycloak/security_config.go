package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v14"
)

func (s *service) ListAuthenticationFlows(ctx context.Context, realm string) ([]AuthFlowInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	flows, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.AuthenticationFlowRepresentation, error) {
		return s.fetchAuthFlows(ctx, token, targetRealm)
	})
	if err != nil {
		return nil, err
	}
	return mapAuthFlows(flows), nil
}

func (s *service) GetFlowExecutions(ctx context.Context, realm, flowAlias string) ([]FlowExecutionInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err = validateIdentifier(flowAlias); err != nil {
		return nil, err
	}
	executions, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ModifyAuthenticationExecutionRepresentation, error) {
		return s.fetchFlowExecutions(ctx, token, targetRealm, flowAlias)
	})
	if err != nil {
		return nil, err
	}
	return mapFlowExecutions(executions), nil
}

func (s *service) ListRequiredActions(ctx context.Context, realm string) ([]RequiredActionInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	actions, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.RequiredActionProviderRepresentation, error) {
		return s.fetchRequiredActions(ctx, token, targetRealm)
	})
	if err != nil {
		return nil, err
	}
	return mapRequiredActions(actions), nil
}

func (s *service) ListIdentityProviders(ctx context.Context, realm string) ([]IdentityProviderInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	providers, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.IdentityProviderRepresentation, error) {
		return s.fetchIdentityProviders(ctx, token, targetRealm)
	})
	if err != nil {
		return nil, err
	}
	return mapIdentityProviders(providers), nil
}

func (s *service) GetIdentityProvider(ctx context.Context, realm, alias string) (IdentityProviderInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return IdentityProviderInfo{}, err
	}
	if err = validateIdentifier(alias); err != nil {
		return IdentityProviderInfo{}, err
	}
	provider, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.IdentityProviderRepresentation, error) {
		return s.fetchIdentityProvider(ctx, token, targetRealm, alias)
	})
	if err != nil {
		return IdentityProviderInfo{}, err
	}
	return mapIdentityProvider(provider), nil
}

func (s *service) ListOrganizations(ctx context.Context, realm string, first, pageSize int, search string) ([]OrganizationInfo, error) {
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
	orgs, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.OrganizationRepresentation, error) {
		return s.fetchOrganizations(ctx, token, targetRealm, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapOrganizations(orgs), nil
}

func (s *service) GetOrganizationMembers(ctx context.Context, realm, orgID string, first, pageSize int, search string) ([]OrganizationMember, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if err = validateIdentifier(orgID); err != nil {
		return nil, err
	}
	if err = validatePagination(first, pageSize); err != nil {
		return nil, err
	}
	if err = validateFilterString(search); err != nil {
		return nil, err
	}
	members, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.MemberRepresentation, error) {
		return s.fetchOrganizationMembers(ctx, token, targetRealm, orgID, first, pageSize, search)
	})
	if err != nil {
		return nil, err
	}
	return mapOrganizationMembers(members), nil
}

func (s *service) fetchAuthFlows(ctx context.Context, token, realm string) ([]*gocloak.AuthenticationFlowRepresentation, error) {
	flows, err := s.client.GetAuthenticationFlows(ctx, token, realm)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return flows, nil
}

func (s *service) fetchFlowExecutions(ctx context.Context, token, realm, flowAlias string) ([]*gocloak.ModifyAuthenticationExecutionRepresentation, error) {
	executions, err := s.client.GetAuthenticationExecutions(ctx, token, realm, flowAlias)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return executions, nil
}

func (s *service) fetchRequiredActions(ctx context.Context, token, realm string) ([]*gocloak.RequiredActionProviderRepresentation, error) {
	actions, err := s.client.GetRequiredActions(ctx, token, realm)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return actions, nil
}

func (s *service) fetchIdentityProviders(ctx context.Context, token, realm string) ([]*gocloak.IdentityProviderRepresentation, error) {
	providers, err := s.client.GetIdentityProviders(ctx, token, realm)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return providers, nil
}

func (s *service) fetchIdentityProvider(ctx context.Context, token, realm, alias string) (*gocloak.IdentityProviderRepresentation, error) {
	provider, err := s.client.GetIdentityProvider(ctx, token, realm, alias)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if provider == nil {
		return nil, errKeycloakRequest
	}
	return provider, nil
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

func mapAuthFlows(flows []*gocloak.AuthenticationFlowRepresentation) []AuthFlowInfo {
	result := make([]AuthFlowInfo, 0, len(flows))
	for _, flow := range flows {
		if flow == nil {
			continue
		}
		result = append(result, AuthFlowInfo{
			ID:          derefString(flow.ID),
			Alias:       derefString(flow.Alias),
			Description: derefString(flow.Description),
			ProviderID:  derefString(flow.ProviderID),
			TopLevel:    derefBool(flow.TopLevel),
			BuiltIn:     derefBool(flow.BuiltIn),
		})
	}
	return result
}

func mapFlowExecutions(executions []*gocloak.ModifyAuthenticationExecutionRepresentation) []FlowExecutionInfo {
	result := make([]FlowExecutionInfo, 0, len(executions))
	for _, exec := range executions {
		if exec == nil {
			continue
		}
		result = append(result, FlowExecutionInfo{
			ID:                 derefString(exec.ID),
			DisplayName:        derefString(exec.DisplayName),
			Alias:              derefString(exec.Alias),
			ProviderID:         derefString(exec.ProviderID),
			Requirement:        derefString(exec.Requirement),
			Level:              derefInt(exec.Level),
			Index:              derefInt(exec.Index),
			AuthenticationFlow: derefBool(exec.AuthenticationFlow),
			Configurable:       derefBool(exec.Configurable),
		})
	}
	return result
}

func mapRequiredActions(actions []*gocloak.RequiredActionProviderRepresentation) []RequiredActionInfo {
	result := make([]RequiredActionInfo, 0, len(actions))
	for _, action := range actions {
		if action == nil {
			continue
		}
		result = append(result, RequiredActionInfo{
			Alias:         derefString(action.Alias),
			Name:          derefString(action.Name),
			ProviderID:    derefString(action.ProviderID),
			Enabled:       derefBool(action.Enabled),
			DefaultAction: derefBool(action.DefaultAction),
			Priority:      derefInt32(action.Priority),
		})
	}
	return result
}

func mapIdentityProviders(providers []*gocloak.IdentityProviderRepresentation) []IdentityProviderInfo {
	result := make([]IdentityProviderInfo, 0, len(providers))
	for _, provider := range providers {
		if provider != nil {
			result = append(result, mapIdentityProvider(provider))
		}
	}
	return result
}

func mapIdentityProvider(provider *gocloak.IdentityProviderRepresentation) IdentityProviderInfo {
	return IdentityProviderInfo{
		Alias:       derefString(provider.Alias),
		InternalID:  derefString(provider.InternalID),
		DisplayName: derefString(provider.DisplayName),
		ProviderID:  derefString(provider.ProviderID),
		Enabled:     derefBool(provider.Enabled),
		TrustEmail:  derefBool(provider.TrustEmail),
		LinkOnly:    derefBool(provider.LinkOnly),
	}
}

func mapOrganizations(orgs []*gocloak.OrganizationRepresentation) []OrganizationInfo {
	result := make([]OrganizationInfo, 0, len(orgs))
	for _, org := range orgs {
		if org == nil {
			continue
		}
		domains := make([]string, 0, len(org.Domains))
		for _, d := range org.Domains {
			if d.Name != nil && *d.Name != "" {
				domains = append(domains, *d.Name)
			}
		}
		result = append(result, OrganizationInfo{
			ID:          derefString(org.ID),
			Name:        derefString(org.Name),
			Alias:       derefString(org.Alias),
			Description: derefString(org.Description),
			Enabled:     derefBool(org.Enabled),
			Domains:     domains,
		})
	}
	return result
}

func mapOrganizationMembers(members []*gocloak.MemberRepresentation) []OrganizationMember {
	result := make([]OrganizationMember, 0, len(members))
	for _, member := range members {
		if member == nil {
			continue
		}
		var membershipType string
		if member.MembershipType != nil {
			membershipType = string(*member.MembershipType)
		}
		result = append(result, OrganizationMember{
			User:           mapUser(&member.User),
			MembershipType: membershipType,
		})
	}
	return result
}
