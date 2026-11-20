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
	Client
	getToken func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error)
}

//nolint:gocritic // GoCloak's interface requires TokenOptions by value.
func (c *tokenClient) GetToken(ctx context.Context, realm string, options gocloak.TokenOptions) (*gocloak.JWT, error) {
	return c.getToken(ctx, realm, options)
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
	provider := NewTokenProvider(client, "realm", "client", "secret", time.Second)
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

func TestTokenProviderCanceledLeaderDoesNotCancelWaiter(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	client := &tokenClient{
		getToken: func(ctx context.Context, _ string, _ gocloak.TokenOptions) (*gocloak.JWT, error) {
			close(entered)
			select {
			case <-release:
				return &gocloak.JWT{AccessToken: "fresh-token", ExpiresIn: 120}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	provider := NewTokenProvider(client, "realm", "client", "secret", 2*time.Second)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := provider.Token(leaderCtx)
		leaderDone <- err
	}()
	<-entered

	waiterDone := make(chan tokenResult, 1)
	go func() {
		tok, err := provider.Token(context.Background())
		waiterDone <- tokenResult{token: tok, err: err}
	}()
	time.Sleep(10 * time.Millisecond)
	cancelLeader()
	if err := <-leaderDone; err == nil {
		t.Fatal("leader error = nil, want cancellation error")
	}

	close(release)
	res := <-waiterDone
	if res.err != nil || res.token != "fresh-token" {
		t.Fatalf("waiter = (%q, %v), want (fresh-token, nil)", res.token, res.err)
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
	}, "realm", "client", "secret", 0)

	_, err := provider.Token(context.Background())
	if err == nil || err.Error() != "token request failed" {
		t.Fatalf("Token() error = %v, want sanitized error", err)
	}
}

func TestTokenProviderRejectsInvalidJWTResponses(t *testing.T) {
	cases := []*gocloak.JWT{
		nil,
		{AccessToken: "", ExpiresIn: 60},
		{AccessToken: "tok", ExpiresIn: 0},
		{AccessToken: "tok", ExpiresIn: -5},
	}
	for _, jwt := range cases {
		provider := NewTokenProvider(&tokenClient{
			getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
				return jwt, nil
			},
		}, "realm", "client", "secret", time.Second)
		if _, err := provider.Token(context.Background()); err == nil {
			t.Errorf("Token() for %+v error = nil, want error", jwt)
		}
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
		timeout:  time.Second,
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

func TestTokenProviderMeasuresExpiryBeforeRequestAndSupportsShortTTL(t *testing.T) {
	now := time.Now()
	var calls atomic.Int32
	provider := &tokenProvider{
		client: &tokenClient{
			getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
				calls.Add(1)
				now = now.Add(3 * time.Second)
				return &gocloak.JWT{AccessToken: "short", ExpiresIn: 4}, nil
			},
		},
		realm:    "realm",
		clientID: "client",
		timeout:  time.Second,
		now:      func() time.Time { return now },
	}
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Request took 3s and 50% TTL of 4s is 2s, so token must already require refresh.
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("GetToken calls = %d, want 2", got)
	}
}

func TestTokenProviderInvalidateForcesRefresh(t *testing.T) {
	var calls atomic.Int32
	provider := NewTokenProvider(&tokenClient{
		getToken: func(context.Context, string, gocloak.TokenOptions) (*gocloak.JWT, error) {
			calls.Add(1)
			return &gocloak.JWT{AccessToken: "access", ExpiresIn: 120}, nil
		},
	}, "realm", "client", "secret", time.Second)

	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	provider.Invalidate()
	if _, err := provider.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("GetToken calls = %d, want 2", got)
	}
}

func TestTokenProviderRejectsCanceledContext(t *testing.T) {
	provider := NewTokenProvider(&tokenClient{}, "realm", "client", "secret", time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Token(ctx); err == nil {
		t.Fatal("Token() with canceled context error = nil")
	}
}
