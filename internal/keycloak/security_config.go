package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v15"
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

func (s *service) GetAuthenticationFlow(ctx context.Context, realm, flowID string) (AuthFlowInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return AuthFlowInfo{}, err
	}
	if valErr := validateIdentifier(flowID); valErr != nil {
		return AuthFlowInfo{}, valErr
	}
	flow, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.AuthenticationFlowRepresentation, error) {
		res, callErr := s.client.GetAuthenticationFlow(ctx, token, targetRealm, flowID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return AuthFlowInfo{}, err
	}
	return mapAuthFlow(flow), nil
}

func (s *service) GetFlowExecutions(ctx context.Context, realm, flowAlias string) ([]FlowExecutionInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(flowAlias); valErr != nil {
		return nil, valErr
	}
	executions, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.ModifyAuthenticationExecutionRepresentation, error) {
		return s.fetchFlowExecutions(ctx, token, targetRealm, flowAlias)
	})
	if err != nil {
		return nil, err
	}
	return mapFlowExecutions(executions), nil
}

func (s *service) GetAuthenticatorConfig(ctx context.Context, realm, configID string) (AuthenticatorConfigInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return AuthenticatorConfigInfo{}, err
	}
	if valErr := validateIdentifier(configID); valErr != nil {
		return AuthenticatorConfigInfo{}, valErr
	}
	cfg, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.AuthenticatorConfigRepresentation, error) {
		res, callErr := s.client.GetAuthenticatorConfig(ctx, token, targetRealm, configID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return AuthenticatorConfigInfo{}, err
	}
	return AuthenticatorConfigInfo{
		ID:     derefString(cfg.ID),
		Alias:  derefString(cfg.Alias),
		Config: sanitizeConfigMap(cfg.Config),
	}, nil
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

func (s *service) GetRequiredAction(ctx context.Context, realm, alias string) (RequiredActionInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RequiredActionInfo{}, err
	}
	if valErr := validateIdentifier(alias); valErr != nil {
		return RequiredActionInfo{}, valErr
	}
	action, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.RequiredActionProviderRepresentation, error) {
		res, callErr := s.client.GetRequiredAction(ctx, token, targetRealm, alias)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return RequiredActionInfo{}, err
	}
	return mapRequiredAction(action), nil
}

func (s *service) ListUnregisteredRequiredActions(ctx context.Context, realm string) ([]UnregisteredRequiredActionInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	actions, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.UnregisteredRequiredActionProviderRepresentation, error) {
		res, callErr := s.client.GetUnregisteredRequiredActions(ctx, token, targetRealm)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]UnregisteredRequiredActionInfo, 0, len(actions))
	for _, a := range actions {
		if a == nil {
			continue
		}
		result = append(result, UnregisteredRequiredActionInfo{
			Name:       sanitizeOutputString(a.Name),
			ProviderID: sanitizeOutputString(a.ProviderID),
		})
	}
	return result, nil
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
	if valErr := validateIdentifier(alias); valErr != nil {
		return IdentityProviderInfo{}, valErr
	}
	provider, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.IdentityProviderRepresentation, error) {
		return s.fetchIdentityProvider(ctx, token, targetRealm, alias)
	})
	if err != nil {
		return IdentityProviderInfo{}, err
	}
	return mapIdentityProvider(provider), nil
}

func (s *service) ListIdentityProviderMappers(ctx context.Context, realm, alias string) ([]IdentityProviderMapperInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	if valErr := validateIdentifier(alias); valErr != nil {
		return nil, valErr
	}
	mappers, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.IdentityProviderMapper, error) {
		res, callErr := s.client.GetIdentityProviderMappers(ctx, token, targetRealm, alias)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]IdentityProviderMapperInfo, 0, len(mappers))
	for _, m := range mappers {
		if m != nil {
			result = append(result, mapIdentityProviderMapper(m))
		}
	}
	return result, nil
}

func (s *service) GetIdentityProviderMapper(ctx context.Context, realm, alias, mapperID string) (IdentityProviderMapperInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return IdentityProviderMapperInfo{}, err
	}
	if valErr := validateIdentifier(alias); valErr != nil {
		return IdentityProviderMapperInfo{}, valErr
	}
	if valErr := validateIdentifier(mapperID); valErr != nil {
		return IdentityProviderMapperInfo{}, valErr
	}
	mapper, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.IdentityProviderMapper, error) {
		res, callErr := s.client.GetIdentityProviderMapperByID(ctx, token, targetRealm, alias, mapperID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return IdentityProviderMapperInfo{}, err
	}
	return mapIdentityProviderMapper(mapper), nil
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

func mapAuthFlows(flows []*gocloak.AuthenticationFlowRepresentation) []AuthFlowInfo {
	result := make([]AuthFlowInfo, 0, len(flows))
	for _, flow := range flows {
		if flow != nil {
			result = append(result, mapAuthFlow(flow))
		}
	}
	return result
}

func mapAuthFlow(flow *gocloak.AuthenticationFlowRepresentation) AuthFlowInfo {
	return AuthFlowInfo{
		ID:          derefString(flow.ID),
		Alias:       derefString(flow.Alias),
		Description: derefString(flow.Description),
		ProviderID:  derefString(flow.ProviderID),
		TopLevel:    derefBool(flow.TopLevel),
		BuiltIn:     derefBool(flow.BuiltIn),
	}
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
		if action != nil {
			result = append(result, mapRequiredAction(action))
		}
	}
	return result
}

func mapRequiredAction(action *gocloak.RequiredActionProviderRepresentation) RequiredActionInfo {
	return RequiredActionInfo{
		Alias:         derefString(action.Alias),
		Name:          derefString(action.Name),
		ProviderID:    derefString(action.ProviderID),
		Enabled:       derefBool(action.Enabled),
		DefaultAction: derefBool(action.DefaultAction),
		Priority:      derefInt32(action.Priority),
	}
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

func mapIdentityProviderMapper(m *gocloak.IdentityProviderMapper) IdentityProviderMapperInfo {
	return IdentityProviderMapperInfo{
		ID:                     derefString(m.ID),
		Name:                   derefString(m.Name),
		IdentityProviderMapper: derefString(m.IdentityProviderMapper),
		IdentityProviderAlias:  derefString(m.IdentityProviderAlias),
		Config:                 sanitizeConfigMap(m.Config),
	}
}
