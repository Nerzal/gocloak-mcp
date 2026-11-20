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

func (c *tokenClient) GetToken(ctx context.Context, realm string, options gocloak.TokenOptions) (*gocloak.JWT, error) {
	return c.getToken(ctx, realm, options)
}

func (*tokenClient) GetUsers(context.Context, string, string, gocloak.GetUsersParams) ([]*gocloak.User, error) {
	return nil, nil
}

func (*tokenClient) GetClients(context.Context, string, string, gocloak.GetClientsParams) ([]*gocloak.Client, error) {
	return nil, nil
}

func (*tokenClient) GetRealm(context.Context, string, string) (*gocloak.RealmRepresentation, error) {
	return nil, nil
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
	results := make(chan string, workers)
	errorsFound := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			token, err := provider.Token(context.Background())
			if err != nil {
				errorsFound <- err
				return
			}
			results <- token
		}()
	}
	<-entered
	time.Sleep(10 * time.Millisecond)
	close(release)
	group.Wait()
	close(results)
	close(errorsFound)

	for err := range errorsFound {
		t.Errorf("Token() error = %v", err)
	}
	for token := range results {
		if token != "access" {
			t.Errorf("Token() = %q, want access", token)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("GetToken calls = %d, want 1", got)
	}
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
