package keycloak

import (
	"context"
	"math"
	"time"

	"github.com/Nerzal/gocloak/v15"
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

func (s *service) ListEvents(ctx context.Context, realm string, first, pageSize int, filter *EventFilter) ([]EventInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	first32, max32, err := validatePaginationInt32(first, pageSize)
	if err != nil {
		return nil, err
	}
	if valErr := validateEventFilter(filter); valErr != nil {
		return nil, valErr
	}
	events, err := runWithTokenRetry(ctx, s.tokens, func(token string) ([]*gocloak.EventRepresentation, error) {
		return s.fetchEvents(ctx, token, targetRealm, first32, max32, filter)
	})
	if err != nil {
		return nil, err
	}
	return mapEvents(events), nil
}

func (s *service) ListAdminEvents(ctx context.Context, realm string, first, pageSize int, filter *AdminEventFilter) ([]AdminEventInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	first32, max32, err := validatePaginationInt32(first, pageSize)
	if err != nil {
		return nil, err
	}
	if valErr := validateAdminEventFilter(filter); valErr != nil {
		return nil, valErr
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

func validateEventFilter(filter *EventFilter) error {
	if filter == nil {
		return nil
	}
	if err := validateFilterSlice(filter.Type); err != nil {
		return err
	}
	for _, value := range [...]string{filter.Client, filter.UserID} {
		if err := validateFilterString(value); err != nil {
			return err
		}
	}
	return validateDateRange(filter.DateFrom, filter.DateTo)
}

func validateAdminEventFilter(filter *AdminEventFilter) error {
	if filter == nil {
		return nil
	}
	if err := validateFilterSlice(filter.OperationTypes); err != nil {
		return err
	}
	if err := validateFilterSlice(filter.ResourceTypes); err != nil {
		return err
	}
	if err := validateFilterString(filter.ResourcePath); err != nil {
		return err
	}
	return validateDateRange(filter.DateFrom, filter.DateTo)
}

func validateDateRange(dateFrom, dateTo string) error {
	for _, value := range [...]string{dateFrom, dateTo} {
		if value == "" {
			continue
		}
		if _, err := time.Parse("2006-01-02", value); err != nil {
			return errInvalidFilter
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

func (s *service) fetchEvents(ctx context.Context, token, realm string, first, pageSize int32, filter *EventFilter) ([]*gocloak.EventRepresentation, error) {
	params := gocloak.GetEventsParams{First: &first, Max: &pageSize}
	if filter != nil {
		params.Type = filter.Type
		params.Client = optionalStringPtr(filter.Client)
		params.UserID = optionalStringPtr(filter.UserID)
		params.DateFrom = optionalStringPtr(filter.DateFrom)
		params.DateTo = optionalStringPtr(filter.DateTo)
	}
	events, err := s.client.GetEvents(ctx, token, realm, params)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	return events, nil
}

func (s *service) fetchAdminEvents(ctx context.Context, token, realm string, first, pageSize int32, filter *AdminEventFilter) ([]*gocloak.AdminEventRepresentation, error) {
	params := gocloak.GetAdminEventsParams{First: &first, Max: &pageSize}
	if filter != nil {
		params.OperationTypes = filter.OperationTypes
		params.ResourceTypes = filter.ResourceTypes
		params.ResourcePath = optionalStringPtr(filter.ResourcePath)
		params.DateFrom = optionalStringPtr(filter.DateFrom)
		params.DateTo = optionalStringPtr(filter.DateTo)
	}
	events, err := s.client.GetAdminEvents(ctx, token, realm, params)
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
			Type:      sanitizeOutputString(event.Type, maxOutputFieldLen),
			RealmID:   sanitizeOutputString(event.RealmID, maxOutputFieldLen),
			ClientID:  sanitizeOutputString(event.ClientID, maxOutputFieldLen),
			UserID:    sanitizeOutputString(event.UserID, maxOutputFieldLen),
			SessionID: sanitizeOutputString(event.SessionID, maxOutputFieldLen),
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
		result = append(result, AdminEventInfo{
			Time:          event.Time,
			OperationType: sanitizeOutputString(event.OperationType, maxOutputFieldLen),
			RealmID:       sanitizeOutputString(event.RealmID, maxOutputFieldLen),
			ResourceType:  sanitizeOutputString(event.ResourceType, maxOutputFieldLen),
			ResourcePath:  sanitizeOutputString(event.ResourcePath, maxOutputFieldLen),
			AuthClientID:  sanitizeOutputString(event.AuthDetails.ClientID, maxOutputFieldLen),
			AuthUserID:    sanitizeOutputString(event.AuthDetails.UserID, maxOutputFieldLen),
		})
	}
	return result
}
