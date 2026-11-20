package keycloak

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Nerzal/gocloak/v14"
)

func TestOWASP_MCP01_SecretExposureBlockedInDTOs(t *testing.T) {
	ctx := context.Background()
	const (
		clientSecret = "super-secret-client-credential"
		idpSecret    = "oidc-idp-client-secret-value"
		adminSecret  = "raw-admin-event-password-hash"
	)
	svc := NewService(&stubClient{
		clients:     []*gocloak.Client{{ID: strP("c1"), ClientID: strP("web"), Secret: strP(clientSecret)}},
		idps:        []*gocloak.IdentityProviderRepresentation{{Alias: strP("okta"), Config: map[string]string{"clientSecret": idpSecret}}},
		adminEvents: []*gocloak.AdminEventRepresentation{{OperationType: strP("CREATE"), Representation: strP(adminSecret)}},
	}, &stubTokenProvider{}, "prod", []string{"prod"})

	clients, err := svc.ListClients(ctx, "prod", 0, 10, ClientFilter{})
	requireOK(t, err, "ListClients")
	idps, err := svc.ListIdentityProviders(ctx, "prod")
	requireOK(t, err, "ListIdentityProviders")
	events, err := svc.ListAdminEvents(ctx, "prod", 0, 10, nil)
	requireOK(t, err, "ListAdminEvents")

	payload, err := json.Marshal(map[string]any{"clients": clients, "idps": idps, "events": events})
	requireOK(t, err, "json.Marshal")
	body := string(payload)
	for _, secret := range []string{clientSecret, idpSecret, adminSecret} {
		if strings.Contains(body, secret) {
			t.Fatalf("serialized DTO leaked secret %q: %s", secret, body)
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
	if _, err := svc.ListEvents(ctx, "prod", 0, 10, &EventFilter{DateFrom: "2026-99-99"}); !errors.Is(err, errInvalidFilter) {
		t.Fatalf("invalid DateFrom error = %v, want errInvalidFilter", err)
	}
}

func TestOWASP_MCP06_OutputSanitizationNeutralizesControlAndBiDiRunes(t *testing.T) {
	dirty := "Alice\x1b[31m\x00\u202eEvil" + strings.Repeat("x", 600)
	clean := sanitizeOutputString(dirty, maxOutputFieldLen)
	if strings.ContainsAny(clean, "\x1b\x00\u202e") {
		t.Fatalf("sanitizeOutputString left unsafe runes: %q", clean)
	}
	if len([]rune(clean)) != maxOutputFieldLen {
		t.Fatalf("len(runes) = %d, want %d", len([]rune(clean)), maxOutputFieldLen)
	}
}
