package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak/v15"
)

func newOWASPSecretFixtureService(markers []string) Service {
	clientFixture := &gocloak.Client{
		ID: strP("c1"), ClientID: strP("web"),
		Secret: strP(markers[0]), RegistrationAccessToken: strP(markers[1]),
		ProtocolMappers: []gocloak.ProtocolMapperRepresentation{{
			ID: strP("pm1"), Name: strP("m1"),
			Config: map[string]string{"claim.name": "org", "clientSecret": markers[10], "script": markers[11]},
		}},
	}
	return NewService(&stubClient{
		clients:     []*gocloak.Client{clientFixture},
		client:      clientFixture,
		idps:        []*gocloak.IdentityProviderRepresentation{{Alias: strP("okta"), Config: map[string]string{"clientSecret": markers[2]}}},
		adminEvents: []*gocloak.AdminEventRepresentation{{OperationType: "CREATE", Representation: markers[3]}},
		creds: []*gocloak.CredentialRepresentation{{
			ID: strP("cr1"), Type: strP("password"),
			SecretData: strP(markers[4]), CredentialData: strP(markers[5]), Value: strP(markers[6]),
		}},
		components: []*gocloak.Component{{
			ID: strP("cmp1"), Name: strP("ldap"),
			ComponentConfig: map[string][]string{"bindCredential": {markers[7]}},
		}},
		invitations: []*gocloak.OrganizationInvitationRepresentation{{
			ID: "inv1", Email: "a@example.com", InviteLink: markers[8],
		}},
		authConfig: &gocloak.AuthenticatorConfigRepresentation{
			ID: strP("ac1"), Alias: strP("cfg"),
			Config: map[string]string{"safeKey": "ok", "api_key": markers[9]},
		},
	}, &stubTokenProvider{}, "prod", []string{"prod"})
}

func TestOWASP_MCP01_SecretExposureBlockedInDTOs(t *testing.T) {
	ctx := context.Background()
	markers := []string{
		"redacted-fixture-01", "redacted-fixture-02", "redacted-fixture-03", "redacted-fixture-04",
		"redacted-fixture-05", "redacted-fixture-06", "redacted-fixture-07", "redacted-fixture-08",
		"https://keycloak.example/invite?m=redacted-fixture-09", "redacted-fixture-10",
		"redacted-fixture-11", "redacted-fixture-12",
	}
	svc := newOWASPSecretFixtureService(markers)

	clients, err := svc.ListClients(ctx, "prod", 0, 10, ClientFilter{})
	requireOK(t, err, "ListClients")
	mappers, err := svc.GetClientProtocolMappers(ctx, "prod", "c1")
	requireOK(t, err, "GetClientProtocolMappers")
	idps, err := svc.ListIdentityProviders(ctx, "prod")
	requireOK(t, err, "ListIdentityProviders")
	events, err := svc.ListAdminEvents(ctx, "prod", 0, 10, nil)
	requireOK(t, err, "ListAdminEvents")
	creds, err := svc.GetUserCredentials(ctx, "prod", "u1")
	requireOK(t, err, "GetUserCredentials")
	comps, err := svc.ListComponents(ctx, "prod", ComponentFilter{})
	requireOK(t, err, "ListComponents")
	invs, err := svc.ListOrganizationInvitations(ctx, "prod", "o1", 0, 10, "")
	requireOK(t, err, "ListOrganizationInvitations")
	authCfg, err := svc.GetAuthenticatorConfig(ctx, "prod", "ac1")
	requireOK(t, err, "GetAuthenticatorConfig")

	payload, err := json.Marshal(map[string]any{
		"clients": clients, "mappers": mappers, "idps": idps, "events": events,
		"creds": creds, "comps": comps, "invs": invs, "authCfg": authCfg,
	})
	requireOK(t, err, "json.Marshal")
	body := string(payload)
	for _, marker := range markers {
		if strings.Contains(body, marker) {
			t.Fatalf("serialized DTO leaked fixture marker %q: %s", marker, body)
		}
	}
}

func TestOWASP_MCP02_ScopeCreepRealmAllowlistEnforced(t *testing.T) {
	ctx := context.Background()
	svc := NewService(&stubClient{
		realms: []*gocloak.RealmRepresentation{
			{ID: strP("1"), Realm: strP("master"), Enabled: boolP(true)},
			{ID: strP("2"), Realm: strP("tenant-a"), Enabled: boolP(true)},
		},
	}, &stubTokenProvider{}, "tenant-a", []string{"tenant-a"})

	realms, err := svc.ListRealms(ctx)
	requireOK(t, err, "ListRealms")
	requireCount(t, len(realms), 1, "ListRealms")
	if realms[0].Name != "tenant-a" {
		t.Fatalf("unexpected realm returned: %+v", realms)
	}
	if _, err := svc.GetRealmInfo(ctx, "master"); !errors.Is(err, errRealmNotAllowed) {
		t.Fatalf("GetRealmInfo(master) error = %v, want errRealmNotAllowed", err)
	}
}

func TestOWASP_MCP05_PathTraversalAndInjectionRejected(t *testing.T) {
	ctx := context.Background()
	svc := NewService(&stubClient{}, &stubTokenProvider{}, "prod", []string{"prod"})

	maliciousIDs := []string{
		"", " ", " valid ", ".", "..", "../admin", `..\admin`,
		"%2e%2e", "id%2fclients", "id?foo=bar", "id#frag",
		"id\x00null", "id\r\nX-Injected: 1", strings.Repeat("a", 256),
	}
	for _, id := range maliciousIDs {
		if _, err := svc.GetUser(ctx, "prod", id); !errors.Is(err, errInvalidID) {
			t.Errorf("GetUser(%q) error = %v, want errInvalidID", id, err)
		}
	}
	maliciousGroupPaths := []string{
		"", " ", "/", "//", "/a//b", "/.", "/..", "/a/../b", "../admin",
		`/a\b`, "/a%2e%2e/b", "/a?x=1", "/a#frag", "/a\x00b",
	}
	for _, path := range maliciousGroupPaths {
		if _, err := svc.GetGroupByPath(ctx, "prod", path); !errors.Is(err, errInvalidID) {
			t.Errorf("GetGroupByPath(%q) error = %v, want errInvalidID", path, err)
		}
	}
	if _, err := svc.ListEvents(ctx, "prod", 0, 10, &EventFilter{DateFrom: "2026-99-99"}); !errors.Is(err, errInvalidFilter) {
		t.Fatalf("invalid DateFrom error = %v, want errInvalidFilter", err)
	}
}

func TestOWASP_MCP06_OutputSanitizationNeutralizesControlAndBiDiRunes(t *testing.T) {
	dirty := "Alice\x1b[31m\x00\u202eEvil" + strings.Repeat("x", 600)
	clean := sanitizeOutputString(dirty)
	if strings.ContainsAny(clean, "\x1b\x00\u202e") {
		t.Fatalf("sanitizeOutputString left unsafe runes: %q", clean)
	}
	if len([]rune(clean)) != maxOutputFieldLen {
		t.Fatalf("len(runes) = %d, want %d", len([]rune(clean)), maxOutputFieldLen)
	}
}
