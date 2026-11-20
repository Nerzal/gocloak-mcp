package keycloak

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v14"
	"golang.org/x/sync/singleflight"
)

const defaultTokenTimeout = 15 * time.Second

// TokenProvider returns a cached access token for Keycloak API requests.
type TokenProvider interface {
	Token(context.Context) (string, error)
	Invalidate()
}

type tokenProvider struct {
	client       Client
	realm        string
	clientID     string
	clientSecret string
	timeout      time.Duration
	now          func() time.Time

	mu        sync.RWMutex
	token     string
	refreshAt time.Time
	requests  singleflight.Group
}

// NewTokenProvider constructs a thread-safe client-credentials token cache.
func NewTokenProvider(client Client, realm, clientID, clientSecret string, timeout time.Duration) TokenProvider {
	if timeout <= 0 {
		timeout = defaultTokenTimeout
	}
	return &tokenProvider{
		client:       client,
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		timeout:      timeout,
		now:          time.Now,
	}
}

func (p *tokenProvider) Invalidate() {
	p.mu.Lock()
	p.token = ""
	p.refreshAt = time.Time{}
	p.mu.Unlock()
}

func (p *tokenProvider) Token(ctx context.Context) (string, error) {
	if token, ok := p.cachedToken(); ok {
		return token, nil
	}
	if ctx.Err() != nil {
		return "", errors.New("token request canceled")
	}

	result := p.requests.DoChan("access-token", func() (any, error) {
		if token, ok := p.cachedToken(); ok {
			return token, nil
		}
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.timeout)
		defer cancel()
		return p.fetchToken(refreshCtx)
	})
	return waitForToken(ctx, result)
}

func waitForToken(ctx context.Context, result <-chan singleflight.Result) (string, error) {
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
	startedAt := p.now()
	clientID := p.clientID
	clientSecret := p.clientSecret
	grantType := "client_credentials"
	token, err := p.client.GetToken(ctx, p.realm, gocloak.TokenOptions{
		ClientID:     &clientID,
		ClientSecret: &clientSecret,
		GrantType:    &grantType,
	})
	if err != nil || !isValidJWT(token) {
		return "", errors.New("token request failed")
	}

	p.storeToken(token.AccessToken, startedAt.Add(refreshDuration(token.ExpiresIn)))
	return token.AccessToken, nil
}

func (p *tokenProvider) storeToken(accessToken string, refreshAt time.Time) {
	p.mu.Lock()
	p.token = accessToken
	p.refreshAt = refreshAt
	p.mu.Unlock()
}

func isValidJWT(token *gocloak.JWT) bool {
	return token != nil &&
		token.AccessToken != "" &&
		token.ExpiresIn > 0 &&
		int64(token.ExpiresIn) <= (1<<63-1)/int64(time.Second)
}

func refreshDuration(expiresIn int) time.Duration {
	ttl := time.Duration(expiresIn) * time.Second
	refreshAfter := ttl - 30*time.Second
	if refreshAfter < ttl/2 {
		refreshAfter = ttl / 2
	}
	return refreshAfter
}
