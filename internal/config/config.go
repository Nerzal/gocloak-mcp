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
	defaultTransport      = "stdio"
	defaultHTTPAddr       = "127.0.0.1:8080"
	minBearerTokenLength  = 32

	// TransportStdio runs the MCP server over stdin/stdout.
	TransportStdio = "stdio"
	// TransportHTTP runs the MCP server over Streamable HTTP.
	TransportHTTP = "http"
)

var realmPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)

// Config contains the validated Keycloak connection and MCP transport settings.
type Config struct {
	KeycloakURL     string
	Realm           string
	AllowedRealms   []string
	ClientID        string
	ClientSecret    string
	RequestTimeout  time.Duration
	Transport       string
	HTTPAddr        string
	HTTPBearerToken string
}

// String returns a redacted representation of Config so secrets are not leaked via fmt.
func (c Config) String() string {
	return "Config{KeycloakURL:" + c.KeycloakURL +
		" Realm:" + c.Realm +
		" ClientID:" + c.ClientID +
		" ClientSecret:[REDACTED]" +
		" RequestTimeout:" + c.RequestTimeout.String() +
		" Transport:" + c.Transport +
		" HTTPAddr:" + c.HTTPAddr +
		" HTTPBearerToken:[REDACTED]}"
}

// LogValue redacts secrets when Config is passed to log/slog.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("keycloak_url", c.KeycloakURL),
		slog.String("realm", c.Realm),
		slog.String("client_id", c.ClientID),
		slog.String("client_secret", "[REDACTED]"),
		slog.Duration("request_timeout", c.RequestTimeout),
		slog.String("transport", c.Transport),
		slog.String("http_addr", c.HTTPAddr),
		slog.String("http_bearer_token", "[REDACTED]"),
	)
}

// Load reads and validates configuration from the process environment.
func Load() (Config, error) {
	cfg := Config{
		KeycloakURL:     os.Getenv("KEYCLOAK_URL"),
		Realm:           os.Getenv("KEYCLOAK_REALM"),
		ClientID:        os.Getenv("KEYCLOAK_CLIENT_ID"),
		ClientSecret:    os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		RequestTimeout:  defaultRequestTimeout,
		Transport:       envOrDefault("MCP_TRANSPORT", defaultTransport),
		HTTPAddr:        envOrDefault("MCP_HTTP_ADDR", defaultHTTPAddr),
		HTTPBearerToken: os.Getenv("MCP_HTTP_BEARER_TOKEN"),
	}

	if err := parseTimeoutEnv(&cfg); err != nil {
		return Config{}, err
	}
	cfg.AllowedRealms = parseAllowedRealms(cfg.Realm, os.Getenv("KEYCLOAK_ALLOWED_REALMS"))
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func parseTimeoutEnv(cfg *Config) error {
	value := os.Getenv("KEYCLOAK_REQUEST_TIMEOUT")
	if value == "" {
		return nil
	}
	timeout, err := time.ParseDuration(value)
	if err != nil {
		return errors.New("KEYCLOAK_REQUEST_TIMEOUT must be a positive duration no greater than 2m")
	}
	cfg.RequestTimeout = timeout
	return nil
}

func parseAllowedRealms(defaultRealm, raw string) []string {
	if strings.TrimSpace(raw) == "" {
		if defaultRealm == "" {
			return nil
		}
		return []string{defaultRealm}
	}
	parts := strings.Split(raw, ",")
	realms := make([]string, 0, len(parts)+1)
	seen := make(map[string]struct{}, len(parts)+1)
	if defaultRealm != "" {
		realms = append(realms, defaultRealm)
		seen[defaultRealm] = struct{}{}
	}
	for _, part := range parts {
		realm := strings.TrimSpace(part)
		if _, exists := seen[realm]; exists {
			continue
		}
		seen[realm] = struct{}{}
		realms = append(realms, realm)
	}
	return realms
}

// Validate checks the Keycloak URL, realms, credentials, timeout, and transport settings.
func (c Config) Validate() error {
	if !isValidKeycloakURL(c.KeycloakURL) {
		return errors.New("KEYCLOAK_URL must use HTTPS (or loopback HTTP) without credentials, query, or fragment")
	}
	if err := validateRealms(c.Realm, c.AllowedRealms); err != nil {
		return err
	}
	if err := validateCredentials(c.ClientID, c.ClientSecret); err != nil {
		return err
	}
	if c.RequestTimeout <= 0 || c.RequestTimeout > maxRequestTimeout {
		return errors.New("KEYCLOAK_REQUEST_TIMEOUT must be a positive duration no greater than 2m")
	}
	return validateTransport(c.Transport, c.HTTPAddr, c.HTTPBearerToken)
}

func validateRealms(defaultRealm string, allowed []string) error {
	if !IsValidRealm(defaultRealm) {
		return errors.New("KEYCLOAK_REALM must be 1-255 letters, digits, dots, underscores, or hyphens")
	}
	for _, realm := range allowed {
		if !IsValidRealm(realm) {
			return errors.New("KEYCLOAK_ALLOWED_REALMS contains an invalid realm name")
		}
	}
	return nil
}

func validateCredentials(clientID, clientSecret string) error {
	if strings.TrimSpace(clientID) == "" {
		return errors.New("KEYCLOAK_CLIENT_ID is required")
	}
	if strings.TrimSpace(clientSecret) == "" {
		return errors.New("KEYCLOAK_CLIENT_SECRET is required")
	}
	return nil
}

func validateTransport(transport, addr, bearerToken string) error {
	if transport == TransportStdio {
		return nil
	}
	if transport != TransportHTTP {
		return errors.New("MCP_TRANSPORT must be stdio or http")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return errors.New("MCP_HTTP_ADDR must be a valid host:port address")
	}
	if !isLoopbackHost(host) && len(strings.TrimSpace(bearerToken)) < minBearerTokenLength {
		return errors.New("MCP_HTTP_BEARER_TOKEN (at least 32 characters) is required when binding MCP_HTTP_ADDR to a non-loopback address")
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

// IsValidRealm reports whether realm is a valid, safe Keycloak realm identifier.
func IsValidRealm(realm string) bool {
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
	return isLoopbackHost(host)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
