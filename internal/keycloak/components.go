package keycloak

import (
	"context"

	"github.com/Nerzal/gocloak/v15"
)

func (s *service) ListComponents(ctx context.Context, realm string, filter ComponentFilter) ([]ComponentInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	for _, value := range [...]string{filter.Name, filter.ProviderType, filter.ParentID} {
		if valErr := validateFilterString(value); valErr != nil {
			return nil, valErr
		}
	}
	components, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.Component, error) {
		res, callErr := s.client.GetComponentsWithParams(ctx, token, targetRealm, gocloak.GetComponentsParams{
			Name:         optionalStringPtr(filter.Name),
			ProviderType: optionalStringPtr(filter.ProviderType),
			ParentID:     optionalStringPtr(filter.ParentID),
		})
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	result := make([]ComponentInfo, 0, len(components))
	for _, c := range components {
		if c != nil {
			result = append(result, mapComponent(c))
		}
	}
	return result, nil
}

func (s *service) GetComponent(ctx context.Context, realm, componentID string) (ComponentInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return ComponentInfo{}, err
	}
	if valErr := validateIdentifier(componentID); valErr != nil {
		return ComponentInfo{}, valErr
	}
	component, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.Component, error) {
		res, callErr := s.client.GetComponent(ctx, token, targetRealm, componentID)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return ComponentInfo{}, err
	}
	return mapComponent(component), nil
}

func mapComponent(c *gocloak.Component) ComponentInfo {
	return ComponentInfo{
		ID:           derefString(c.ID),
		Name:         derefString(c.Name),
		ProviderID:   derefString(c.ProviderID),
		ProviderType: derefString(c.ProviderType),
		ParentID:     derefString(c.ParentID),
		SubType:      derefString(c.SubType),
	}
}
