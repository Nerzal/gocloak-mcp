// Package config loads and validates the server's environment configuration.
package config

import (
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	defaultRequestTimeout = 15 * time.Second
	maxRequestTimeout     = 2 * time.Minute
)

var realmPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)

// Config contains the validated Keycloak connection settings.
type Config struct {
	KeycloakURL    string
	Realm          string
	ClientID       string
	ClientSecret   string
	RequestTimeout time.Duration
}

// String returns a redacted representation of Config so secrets are not leaked via fmt.
func (c Config) String() string {
	return "Config{KeycloakURL:" + c.KeycloakURL +
		" Realm:" + c.Realm +
		" ClientID:" + c.ClientID +
		" ClientSecret:[REDACTED]" +
		" RequestTimeout:" + c.RequestTimeout.String() + "}"
}

// LogValue redacts ClientSecret when Config is passed to log/slog.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("keycloak_url", c.KeycloakURL),
		slog.String("realm", c.Realm),
		slog.String("client_id", c.ClientID),
		slog.String("client_secret", "[REDACTED]"),
		slog.Duration("request_timeout", c.RequestTimeout),
	)
}

// Load reads and validates configuration from the process environment.
func Load() (Config, error) {
	cfg := Config{
		KeycloakURL:    os.Getenv("KEYCLOAK_URL"),
		Realm:          os.Getenv("KEYCLOAK_REALM"),
		ClientID:       os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret:   os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		RequestTimeout: defaultRequestTimeout,
	}

	if value := os.Getenv("KEYCLOAK_REQUEST_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, errors.New("KEYCLOAK_REQUEST_TIMEOUT must be a positive duration no greater than 2m")
		}
		cfg.RequestTimeout = timeout
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the Keycloak URL, realm, service-account credentials, and timeout.
func (c Config) Validate() error {
	if !isValidKeycloakURL(c.KeycloakURL) {
		return errors.New("KEYCLOAK_URL must use HTTPS (or loopback HTTP) without credentials, query, or fragment")
	}
	if !isValidRealm(c.Realm) {
		return errors.New("KEYCLOAK_REALM must be 1-255 letters, digits, dots, underscores, or hyphens")
	}
	if strings.TrimSpace(c.ClientID) == "" {
		return errors.New("KEYCLOAK_CLIENT_ID is required")
	}
	if strings.TrimSpace(c.ClientSecret) == "" {
		return errors.New("KEYCLOAK_CLIENT_SECRET is required")
	}
	if c.RequestTimeout <= 0 || c.RequestTimeout > maxRequestTimeout {
		return errors.New("KEYCLOAK_REQUEST_TIMEOUT must be a positive duration no greater than 2m")
	}
	return nil
}

func isValidKeycloakURL(rawURL string) bool {
	if strings.ContainsAny(rawURL, "?#") {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return isAllowedKeycloakURL(parsed)
}

func isValidRealm(realm string) bool {
	return realm != "." && realm != ".." && realmPattern.MatchString(realm)
}

func isAllowedKeycloakURL(parsed *url.URL) bool {
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}
