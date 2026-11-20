package keycloak

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v14"
)

type tokenClient struct {
	getToken func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error)
}

//nolint:gocritic // GoCloak's interface requires TokenOptions by value.
func (c *tokenClient) GetToken(ctx context.Context, realm string, options gocloak.TokenOptions) (*gocloak.JWT, error) {
	return c.getToken(ctx, realm, options)
}

func (*tokenClient) GetUsers(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error) {
	return []*gocloak.User{}, nil
}

func (*tokenClient) GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	return []*gocloak.Client{}, nil
}

func (*tokenClient) GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error) {
	return &gocloak.RealmRepresentation{}, nil
}

func TestTokenProviderSharesConcurrentRequest(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	client := &tokenClient{
		getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
			calls.Add(1)
			close(entered)
			<-release
			return &gocloak.JWT{AccessToken: "access", ExpiresIn: 120}, nil
		},
	}
	provider := NewTokenProvider(client, "realm", "client", "secret")
	const workers = 24
	results := concurrentTokenResults(provider, workers)
	<-entered
	time.Sleep(10 * time.Millisecond)
	close(release)

	for result := range results {
		if result.err != nil {
			t.Errorf("Token() error = %v", result.err)
		} else if result.token != "access" {
			t.Errorf("Token() = %q, want access", result.token)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("GetToken calls = %d, want 1", got)
	}
}

type tokenResult struct {
	token string
	err   error
}

func concurrentTokenResults(provider TokenProvider, workers int) <-chan tokenResult {
	results := make(chan tokenResult, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			token, err := provider.Token(context.Background())
			results <- tokenResult{token: token, err: err}
		}()
	}
	go func() {
		group.Wait()
		close(results)
	}()
	return results
}

func TestTokenProviderSanitizesUpstreamError(t *testing.T) {
	provider := NewTokenProvider(&tokenClient{
		getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
			return nil, errors.New("request failed with secret-value")
		},
	}, "realm", "client", "secret")

	_, err := provider.Token(context.Background())
	if err == nil || err.Error() != "token request failed" {
		t.Fatalf("Token() error = %v, want sanitized error", err)
	}
}

func TestTokenProviderRefreshesBeforeExpiration(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	provider := &tokenProvider{
		client: &tokenClient{
			getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
				calls.Add(1)
				return &gocloak.JWT{AccessToken: "access", ExpiresIn: 120}, nil
			},
		},
		realm:    "realm",
		clientID: "client",
		now:      func() time.Time { return now },
	}
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(91 * time.Second)
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("GetToken calls = %d, want 2", got)
	}
}
