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

func (s *service) GetRealmKeys(ctx context.Context, realm string) (RealmKeysInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RealmKeysInfo{}, err
	}
	ks, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.KeyStoreConfig, error) {
		res, callErr := s.client.GetKeyStoreConfig(ctx, token, targetRealm)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return RealmKeysInfo{}, err
	}
	return mapRealmKeys(ks), nil
}

func (s *service) GetRealmCerts(ctx context.Context, realm string) ([]JWKInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return nil, err
	}
	certs, err := s.client.GetCerts(ctx, targetRealm)
	if err != nil {
		return nil, classifyUpstreamError(err)
	}
	if certs == nil {
		return []JWKInfo{}, nil
	}
	return mapCerts(certs.Keys), nil
}

func (s *service) GetRealmIssuer(ctx context.Context, realm string) (RealmIssuerInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return RealmIssuerInfo{}, err
	}
	issuer, err := s.client.GetIssuer(ctx, targetRealm)
	if err != nil {
		return RealmIssuerInfo{}, classifyUpstreamError(err)
	}
	if issuer == nil {
		return RealmIssuerInfo{}, errKeycloakRequest
	}
	return RealmIssuerInfo{
		Realm:           sanitizeOutputString(issuer.Realm),
		PublicKey:       sanitizeOutputString(issuer.PublicKey),
		TokenService:    sanitizeOutputString(issuer.TokenService),
		AccountService:  sanitizeOutputString(issuer.AccountService),
		TokensNotBefore: issuer.TokensNotBefore,
	}, nil
}

func (s *service) GetUserProfileConfig(ctx context.Context, realm string) (UserProfileConfigInfo, error) {
	targetRealm, err := s.resolveRealm(realm)
	if err != nil {
		return UserProfileConfigInfo{}, err
	}
	cfg, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.UserProfileConfig, error) {
		res, callErr := s.client.GetUserProfileConfig(ctx, token, targetRealm)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return UserProfileConfigInfo{}, err
	}
	return mapUserProfileConfig(cfg), nil
}

func (s *service) GetServerInfo(ctx context.Context) (ServerInfo, error) {
	info, err := runWithTokenRetry(ctx, s.tokens, func(token string) (*gocloak.ServerInfoRepresentation, error) {
		res, callErr := s.client.GetServerInfo(ctx, token)
		if callErr != nil {
			return nil, classifyUpstreamError(callErr)
		}
		if res == nil {
			return nil, errKeycloakRequest
		}
		return res, nil
	})
	if err != nil {
		return ServerInfo{}, err
	}
	return ServerInfo{
		Version:    sanitizeOutputString(info.SystemInfo.Version),
		ServerTime: sanitizeOutputString(info.SystemInfo.ServerTime),
		Uptime:     sanitizeOutputString(info.SystemInfo.Uptime),
		JavaVendor: sanitizeOutputString(info.SystemInfo.JavaVendor),
		JavaVM:     sanitizeOutputString(info.SystemInfo.JavaVM),
		OSName:     sanitizeOutputString(info.SystemInfo.OSName),
		OSArch:     sanitizeOutputString(info.SystemInfo.OSArchitecture),
	}, nil
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
		ID:                          derefString(realm.ID),
		Name:                        derefString(realm.Realm),
		DisplayName:                 derefString(realm.DisplayName),
		Enabled:                     derefBool(realm.Enabled),
		SSLRequired:                 derefString(realm.SSLRequired),
		BruteForceProtected:         derefBool(realm.BruteForceProtected),
		RegistrationAllowed:         derefBool(realm.RegistrationAllowed),
		ResetPasswordAllowed:        derefBool(realm.ResetPasswordAllowed),
		RememberMe:                  derefBool(realm.RememberMe),
		VerifyEmail:                 derefBool(realm.VerifyEmail),
		LoginWithEmailAllowed:       derefBool(realm.LoginWithEmailAllowed),
		DuplicateEmailsAllowed:      derefBool(realm.DuplicateEmailsAllowed),
		EventsEnabled:               derefBool(realm.EventsEnabled),
		AdminEventsEnabled:          derefBool(realm.AdminEventsEnabled),
		PasswordPolicy:              derefString(realm.PasswordPolicy),
		DefaultSignatureAlgorithm:   derefString(realm.DefaultSignatureAlgorithm),
		BrowserFlow:                 derefString(realm.BrowserFlow),
		DirectGrantFlow:             derefString(realm.DirectGrantFlow),
		RegistrationFlow:            derefString(realm.RegistrationFlow),
		OrganizationsEnabled:        derefBool(realm.OrganizationsEnabled),
		InternationalizationEnabled: derefBool(realm.InternationalizationEnabled),
		DefaultLocale:               derefString(realm.DefaultLocale),
		LoginTheme:                  derefString(realm.LoginTheme),
		AccessTokenLifespan:         derefInt(realm.AccessTokenLifespan),
		SSOSessionIdleTimeout:       derefInt(realm.SSOSessionIdleTimeout),
		SSOSessionMaxLifespan:       derefInt(realm.SSOSessionMaxLifespan),
	}
}

func mapRealmKeys(ks *gocloak.KeyStoreConfig) RealmKeysInfo {
	keys := make([]RealmKeyInfo, 0, len(ks.Key))
	for i := range ks.Key {
		k := &ks.Key[i]
		keys = append(keys, RealmKeyInfo{
			ProviderID:       sanitizeOutputString(k.ProviderID),
			ProviderPriority: k.ProviderPriority,
			Kid:              sanitizeOutputString(k.Kid),
			Status:           sanitizeOutputString(k.Status),
			Type:             sanitizeOutputString(k.Type),
			Algorithm:        sanitizeOutputString(k.Algorithm),
			PublicKey:        sanitizeOutputString(k.PublicKey),
		})
	}
	return RealmKeysInfo{
		ActiveHS256: sanitizeOutputString(ks.ActiveKeys.HS256),
		ActiveRS256: sanitizeOutputString(ks.ActiveKeys.RS256),
		ActiveAES:   sanitizeOutputString(ks.ActiveKeys.AES),
		Keys:        keys,
	}
}

func mapCerts(keys []gocloak.CertResponseKey) []JWKInfo {
	result := make([]JWKInfo, 0, len(keys))
	for i := range keys {
		k := &keys[i]
		result = append(result, JWKInfo{
			Kid:     sanitizeOutputString(k.Kid),
			Kty:     sanitizeOutputString(k.Kty),
			Alg:     sanitizeOutputString(k.Alg),
			Use:     sanitizeOutputString(k.Use),
			Crv:     sanitizeOutputString(k.Crv),
			KeyOps:  sanitizeStringSlice(k.KeyOps),
			X5t:     sanitizeOutputString(k.X5t),
			X5tS256: sanitizeOutputString(k.X5tS256),
		})
	}
	return result
}

func mapUserProfileConfig(cfg *gocloak.UserProfileConfig) UserProfileConfigInfo {
	attrs := make([]UserProfileAttributeInfo, 0, len(cfg.Attributes))
	for i := range cfg.Attributes {
		a := &cfg.Attributes[i]
		attrs = append(attrs, UserProfileAttributeInfo{
			Name:        derefString(a.Name),
			DisplayName: derefString(a.DisplayName),
			Group:       derefString(a.Group),
			MultiValued: derefBool(a.MultiValued),
		})
	}
	groups := make([]UserProfileGroupInfo, 0, len(cfg.Groups))
	for i := range cfg.Groups {
		g := &cfg.Groups[i]
		groups = append(groups, UserProfileGroupInfo{
			Name:               derefString(g.Name),
			DisplayHeader:      derefString(g.DisplayHeader),
			DisplayDescription: derefString(g.DisplayDescription),
		})
	}
	return UserProfileConfigInfo{
		UnmanagedAttributePolicy: sanitizeOutputString(string(cfg.UnmanagedAttributePolicy)),
		Attributes:               attrs,
		Groups:                   groups,
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
			Type:      sanitizeOutputString(event.Type),
			RealmID:   sanitizeOutputString(event.RealmID),
			ClientID:  sanitizeOutputString(event.ClientID),
			UserID:    sanitizeOutputString(event.UserID),
			SessionID: sanitizeOutputString(event.SessionID),
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
			OperationType: sanitizeOutputString(event.OperationType),
			RealmID:       sanitizeOutputString(event.RealmID),
			ResourceType:  sanitizeOutputString(event.ResourceType),
			ResourcePath:  sanitizeOutputString(event.ResourcePath),
			AuthClientID:  sanitizeOutputString(event.AuthDetails.ClientID),
			AuthUserID:    sanitizeOutputString(event.AuthDetails.UserID),
		})
	}
	return result
}
