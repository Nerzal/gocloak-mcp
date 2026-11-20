package keycloak

import (
	"context"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v14"
)

func BenchmarkTokenProviderCachedHit(b *testing.B) {
	ctx := context.Background()
	provider := NewTokenProvider(&tokenClient{
		getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
			return &gocloak.JWT{AccessToken: "bench-token", ExpiresIn: 300}, nil
		},
	}, "realm", "client", "secret", time.Second)
	if _, err := provider.Token(ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := provider.Token(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokenProviderCachedHitParallel(b *testing.B) {
	ctx := context.Background()
	provider := NewTokenProvider(&tokenClient{
		getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
			return &gocloak.JWT{AccessToken: "bench-token", ExpiresIn: 300}, nil
		},
	}, "realm", "client", "secret", time.Second)
	if _, err := provider.Token(ctx); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := provider.Token(ctx); err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkListUsers100(b *testing.B) {
	ctx := context.Background()
	users := make([]*gocloak.User, 100)
	for i := range users {
		users[i] = &gocloak.User{
			ID:        strP("550e8400-e29b-41d4-a716-446655440000"),
			Username:  strP("alice.example"),
			Email:     strP("alice@example.test"),
			FirstName: strP("Alice"),
			LastName:  strP("Example"),
			Enabled:   boolP(true),
		}
	}
	svc := NewService(&stubClient{users: users}, &stubTokenProvider{}, "prod", []string{"prod"})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := svc.ListUsers(ctx, "prod", 0, 100, UserFilter{Search: "ali"}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateIdentifier(b *testing.B) {
	const id = "550e8400-e29b-41d4-a716-446655440000"
	b.ReportAllocs()
	for b.Loop() {
		if err := validateIdentifier(id); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSanitizeOutputStringClean(b *testing.B) {
	const text = "Standard Keycloak client description without unsafe characters"
	b.ReportAllocs()
	for b.Loop() {
		_ = sanitizeOutputString(text, maxOutputFieldLen)
	}
}
