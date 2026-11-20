package keycloak

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v14"
	"golang.org/x/sync/singleflight"
)

// TokenProvider returns a cached access token for Keycloak API requests.
type TokenProvider interface {
	Token(context.Context) (string, error)
}

type tokenProvider struct {
	client       Client
	realm        string
	clientID     string
	clientSecret string
	now          func() time.Time

	mu        sync.RWMutex
	token     string
	refreshAt time.Time
	requests  singleflight.Group
}

// NewTokenProvider constructs a thread-safe client-credentials token cache.
func NewTokenProvider(client Client, realm, clientID, clientSecret string) TokenProvider {
	return &tokenProvider{
		client:       client,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		now:          time.Now,
	}
}

func (p *tokenProvider) Token(ctx context.Context) (string, error) {
	if token, ok := p.cachedToken(); ok {
		return token, nil
	}

	result := p.requests.DoChan("access-token", func() (any, error) {
		if token, ok := p.cachedToken(); ok {
			return token, nil
		}
		return p.fetchToken(ctx)
	})
	select {
	case <-ctx.Done():
		return "", errors.New("token request canceled")
	case response := <-result:
		if response.Err != nil {
			return "", errors.New("token request failed")
		}
		token, ok := response.Val.(string)
		if !ok {
			return "", errors.New("token request failed")
		}
		return token, nil
	}
}

func (p *tokenProvider) cachedToken() (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.token, p.token != "" && p.now().Before(p.refreshAt)
}

func (p *tokenProvider) fetchToken(ctx context.Context) (string, error) {
	clientID := p.clientID
	clientSecret := p.clientSecret
	grantType := "client_credentials"
	token, err := p.client.GetToken(ctx, p.realm, gocloak.TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    &grantType,
	})
	if err != nil || token == nil || token.AccessToken == "" || token.ExpiresIn <= 0 ||
		int64(token.ExpiresIn) > (1<<63-1)/int64(time.Second) {
		return "", errors.New("token request failed")
	}

	now := p.now()
	ttl := time.Duration(token.ExpiresIn) * time.Second
	refreshAfter := ttl - 30*time.Second
	if refreshAfter < ttl/2 {
		refreshAfter = ttl / 2
	}
	p.mu.Lock()
	p.token = token.AccessToken
	p.refreshAt = now.Add(refreshAfter)
	p.mu.Unlock()
	return token.AccessToken, nil
}
