# gocloak-mcp

A read-only Keycloak MCP server built in Go with the official MCP Go SDK and
GoCloak. It communicates over MCP Stdio; standard output is reserved for the
JSON-RPC protocol and structured logs are written to standard error.

## Requirements

- Go 1.25 or newer
- A Keycloak confidential client with service accounts enabled
- A client secret supplied through the environment

## Configuration

The server validates configuration before it starts and exits without printing
configuration values when validation fails.

| Environment variable | Required | Default | Description |
| --- | --- | --- | --- |
| `KEYCLOAK_URL` | Yes | — | HTTPS Keycloak base URL, such as `https://keycloak.example.com` (a `/auth` prefix is allowed); loopback HTTP is allowed for local development |
| `KEYCLOAK_REALM` | Yes | — | Realm whose data is exposed |
| `KEYCLOAK_CLIENT_ID` | Yes | — | Service-account client ID |
| `KEYCLOAK_CLIENT_SECRET` | Yes | — | Service-account client secret |
| `KEYCLOAK_REQUEST_TIMEOUT` | No | `15s` | Per-request timeout; valid range is greater than zero and at most `2m` |

Use your deployment platform's secret manager to provide the client secret. Do
not put credentials in command-line arguments, configuration files, or logs.

## Minimal Keycloak permissions

Create a dedicated confidential client with service accounts enabled in the
target realm. Assign only the realm-management roles required by your Keycloak
version and enabled fine-grained permissions:

- `query-users` and `view-users` to list users
- `query-clients` and `view-clients` to list clients
- `view-realm` to read realm information

Do not use the `master` realm or grant `realm-admin`. Keycloak role behavior can
differ between releases and fine-grained admin permissions; verify the service
account's access against your deployed Keycloak version.

## Run

```sh
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=example
export KEYCLOAK_CLIENT_ID=gocloak-mcp
export KEYCLOAK_CLIENT_SECRET='<injected by your secret manager>'
go run ./cmd/keycloak-mcp
```

Configure an MCP host to launch the built executable with the same environment
variables. For example, an MCP client configuration may look like:

```json
{
  "mcpServers": {
    "keycloak": {
      "command": "/usr/local/bin/keycloak-mcp",
      "env": {
        "KEYCLOAK_URL": "https://keycloak.example.com",
        "KEYCLOAK_REALM": "example",
        "KEYCLOAK_CLIENT_ID": "gocloak-mcp",
        "KEYCLOAK_CLIENT_SECRET": "${KEYCLOAK_CLIENT_SECRET}"
      }
    }
  }
}
```

Ensure your MCP host expands the secret reference or injects the environment
variable securely; do not replace it with a literal secret.

## Tools

- `list_users`: Returns a page of users (`first` offset and `max` page size;
  defaults to 0 and 50; maximum page size is 100). Returns only user ID,
  username, email, and enabled state.
- `list_clients`: Returns a page of clients with ID, client ID, display name,
  enabled state, and public-client state.
- `get_realm_info`: Returns the configured realm's ID, name, display name, and
  enabled state.

All tools are read-only. Responses use a bounded page size. Keycloak failures
are replaced with a generic tool error; credentials, tokens, raw HTTP response
bodies, and stack traces are not returned or logged.

## Build and verification

```sh
make build
make test
make test-race
make lint
make vuln
make check
```

The lint and security targets require `golangci-lint`, `govulncheck`, and
`gosec` on `PATH`. `make check` runs formatting/lint, tests with the race
detector, vet, vulnerability scans, and a static build.

## Container

```sh
docker build -t gocloak-mcp .
```

The image contains a static binary on `gcr.io/distroless/static-debian12:nonroot`.
Provide configuration as environment variables and mount no writable paths.
