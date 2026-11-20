// Package config loads and validates the server's environment configuration.
package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
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

// Load reads and validates configuration from the process environment.
func Load() (Config, error) {
	cfg := Config{
		KeycloakURL:    os.Getenv("KEYCLOAK_URL"),
		Realm:          os.Getenv("KEYCLOAK_REALM"),
		ClientID:       os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret:   os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		RequestTimeout: defaultRequestTimeout,
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	if value := os.Getenv("KEYCLOAK_REQUEST_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil || timeout <= 0 || timeout > maxRequestTimeout {
			return Config{}, errors.New("KEYCLOAK_REQUEST_TIMEOUT must be a positive duration no greater than 2m")
		}
		cfg.RequestTimeout = timeout
	}
	return cfg, nil
}

// Validate checks the Keycloak URL, realm, and service-account credentials.
func (c Config) Validate() error {
	parsed, err := url.Parse(c.KeycloakURL)
	if err != nil || !isAllowedKeycloakURL(parsed) ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("KEYCLOAK_URL must use HTTPS (or loopback HTTP) without credentials, query, or fragment")
	}
	if !realmPattern.MatchString(c.Realm) {
		return errors.New("KEYCLOAK_REALM must be 1-255 letters, digits, dots, underscores, or hyphens")
	}
	if c.ClientID == "" {
		return errors.New("KEYCLOAK_CLIENT_ID is required")
	}
	if c.ClientSecret == "" {
		return errors.New("KEYCLOAK_CLIENT_SECRET is required")
	}
	return nil
}

func isAllowedKeycloakURL(parsed *url.URL) bool {
	if parsed.Hostname() == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || net.ParseIP(host).IsLoopback()
}
