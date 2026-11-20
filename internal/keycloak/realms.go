package keycloak

import (
	"context"
	"math"

	"github.com/Nerzal/gocloak/v14"
)

func (s *service) ListRealms(ctx context.Context) ([]RealmInfo, error) {
	realms, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.RealmRepresentation, error) {
		return s.fetchRealms(ctx, token)
	})
	if err != nil {
		return nil, err
	}
	return filterAllowedRealms(realms, s.allowedRealms), nil
}

func (s *service) GetRealmInfo(ctx context.Context, realm string) (RealmInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RealmInfo{}, err
	}
	rep, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.RealmRepresentation, error) {
		return s.fetchRealm(ctx, token, targetRealm)
	})
	if err != nil {
		return RealmInfo{}, err
	}
	return mapRealm(rep), nil
}

func (s *service) ListEvents(ctx context.Context, realm string, first, pageSize int, filter EventFilter) ([]EventInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	first32, max32, err := validatePaginationInt32(first, pageSize)
	if err != nil {
		return nil, err
	}
	if err := validateEventFilter(filter); err != nil {
		return nil, err
	}
	events, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.EventRepresentation, error) {
		return s.fetchEvents(ctx, token, targetRealm, first32, max32, filter)
	})
	if err != nil {
		return nil, err
	}
	return mapEvents(events), nil
}

func (s *service) ListAdminEvents(ctx context.Context, realm string, first, pageSize int, filter AdminEventFilter) ([]AdminEventInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	first32, max32, err := validatePaginationInt32(first, pageSize)
	if err != nil {
		return nil, err
	}
	if err := validateAdminEventFilter(filter); err != nil {
		return nil, err
	}
	events, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.AdminEventRepresentation, error) {
		return s.fetchAdminEvents(ctx, token, targetRealm, first32, max32, filter)
	})
	if err != nil {
		return nil, err
	}
	return mapAdminEvents(events), nil
}

func validatePaginationInt32(first, pageSize int) (first32, max32 int32, err error) {
	if first < 0 || first > math.MaxInt32 || pageSize < 1 || pageSize > maxPageSize {
		return 0, 0, errInvalidPage
	}
	return int32(first), int32(pageSize), nil
}

func validateEventFilter(filter EventFilter) error {
	if err := validateFilterSlice(filter.Type); err != nil {
		return err
	}
	for _, value := range [...]string{filter.Client, filter.UserID, filter.DateFrom, filter.DateTo} {
		if err := validateFilterString(value); err != nil {
			return err
		}
	}
	return nil
}

func validateAdminEventFilter(filter AdminEventFilter) error {
	if err := validateFilterSlice(filter.OperationTypes); err != nil {
		return err
	}
	if err := validateFilterSlice(filter.ResourceTypes); err != nil {
		return err
	}
	for _, value := range [...]string{filter.ResourcePath, filter.DateFrom, filter.DateTo} {
		if err := validateFilterString(value); err != nil {
			return err
		}
	}
	return nil
}

func (s *service) fetchRealms(ctx context.Context, token string) ([]*gocloak.RealmRepresentation, error) {
	realms, err := s.client.GetRealms(ctx, token)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return realms, nil
}

func (s *service) fetchRealm(ctx context.Context, token, realm string) (*gocloak.RealmRepresentation, error) {
	rep, err := s.client.GetRealm(ctx, token, realm)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if rep == nil {
		return nil, errKeycloakRequest
	}
	return rep, nil
}

func (s *service) fetchEvents(ctx context.Context, token, realm string, first, pageSize int32, filter EventFilter) ([]*gocloak.EventRepresentation, error) {
	events, err := s.client.GetEvents(ctx, token, realm, gocloak.GetEventsParams{
		Type:     filter.Type,
		Client:   optionalStringPtr(filter.Client),
		UserID:   optionalStringPtr(filter.UserID),
		DateFrom: optionalStringPtr(filter.DateFrom),
		DateTo:   optionalStringPtr(filter.DateTo),
		First:    &first,
		Max:      &pageSize,
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return events, nil
}

func (s *service) fetchAdminEvents(ctx context.Context, token, realm string, first, pageSize int32, filter AdminEventFilter) ([]*gocloak.AdminEventRepresentation, error) {
	events, err := s.client.GetAdminEvents(ctx, token, realm, gocloak.GetAdminEventsParams{
		OperationTypes: filter.OperationTypes,
		ResourceTypes:  filter.ResourceTypes,
		ResourcePath:   optionalStringPtr(filter.ResourcePath),
		DateFrom:       optionalStringPtr(filter.DateFrom),
		DateTo:         optionalStringPtr(filter.DateTo),
		First:          &first,
		Max:            &pageSize,
	})
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return events, nil
}

func filterAllowedRealms(realms []*gocloak.RealmRepresentation, allowed map[string]struct{}) []RealmInfo {
	result := make([]RealmInfo, 0, len(realms))
	for _, rep := range realms {
		if rep == nil {
			continue
		}
		info := mapRealm(rep)
		if _, ok := allowed[info.Name]; ok {
			result = append(result, info)
		}
	}
	return result
}

func mapRealm(realm *gocloak.RealmRepresentation) RealmInfo {
	return RealmInfo{
		ID:          derefString(realm.ID),
		Name:        derefString(realm.Realm),
		DisplayName: derefString(realm.DisplayName),
		Enabled:     derefBool(realm.Enabled),
	}
}

func mapEvents(events []*gocloak.EventRepresentation) []EventInfo {
	result := make([]EventInfo, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		result = append(result, EventInfo{
			Time:      event.Time,
			Type:      derefString(event.Type),
			RealmID:   derefString(event.RealmID),
			ClientID:  derefString(event.ClientID),
			UserID:    derefString(event.UserID),
			SessionID: derefString(event.SessionID),
		})
	}
	return result
}

func mapAdminEvents(events []*gocloak.AdminEventRepresentation) []AdminEventInfo {
	result := make([]AdminEventInfo, 0, len(events))
	for _, event := range events {
		if event == nil {
			continue
		}
		info := AdminEventInfo{
			Time:          event.Time,
			OperationType: derefString(event.OperationType),
			RealmID:       derefString(event.RealmID),
			ResourceType:  derefString(event.ResourceType),
			ResourcePath:  derefString(event.ResourcePath),
		}
		if event.AuthDetails != nil {
			info.AuthClientID = derefString(event.AuthDetails.ClientID)
			info.AuthUserID = derefString(event.AuthDetails.UserID)
		}
		result = append(result, info)
	}
	return result
}
