# gocloak-mcp

A security-first, read-only Keycloak MCP server built in Go with the official
MCP Go SDK and GoCloak v14. Supports **Stdio** (default) and **Streamable HTTP**
transports, multi-realm allowlisting, and full read-only parity across Users,
Clients, Client Scopes, Roles, Groups, Realms, Events, Authentication Flows,
Required Actions, Identity Providers, and Keycloak 26+ Organizations.

In Stdio mode, standard output is strictly reserved for JSON-RPC frames and all
structured JSON logs are written to standard error with automatic redaction.

## Requirements

- Go 1.26.11 or newer
- A Keycloak confidential client with service accounts enabled
- A client secret supplied through the environment

## Configuration

The server validates configuration before it starts and exits without printing
secrets when validation fails.

| Environment variable | Required | Default | Description |
| --- | --- | --- | --- |
| `KEYCLOAK_URL` | Yes | — | HTTPS Keycloak base URL (a `/auth` prefix is allowed); loopback HTTP is allowed for local development |
| `KEYCLOAK_REALM` | Yes | — | Default target realm and token-issuing realm |
| `KEYCLOAK_ALLOWED_REALMS` | No | `KEYCLOAK_REALM` | Comma-separated allowlist of realms tools may query (`KEYCLOAK_REALM` is always included) |
| `KEYCLOAK_CLIENT_ID` | Yes | — | Service-account client ID |
| `KEYCLOAK_CLIENT_SECRET` | Yes | — | Service-account client secret |
| `KEYCLOAK_REQUEST_TIMEOUT` | No | `15s` | Per-request timeout; valid range is `> 0` and `<= 2m` |
| `MCP_TRANSPORT` | No | `stdio` | Transport mode: `stdio` or `http` (Streamable HTTP) |
| `MCP_HTTP_ADDR` | No | `127.0.0.1:8080` | Listen address when `MCP_TRANSPORT=http` |
| `MCP_HTTP_BEARER_TOKEN` | Conditional | — | Optional on loopback; **required (min 32 chars)** when `MCP_HTTP_ADDR` binds to a non-loopback address |

Use your deployment platform's secret manager to provide secrets. Do not put
credentials in command-line arguments, configuration files, or logs.

## Minimal Keycloak permissions

Create a dedicated confidential client with service accounts enabled and assign
only the read-only `realm-management` roles required for the tools you use:

- `query-users`, `view-users` — user, session, and group-membership tools
- `query-clients`, `view-clients` — client, client-role, and client-scope tools
- `query-groups` — group tools
- `view-realm` — realm, role, auth-flow, required-action, and IdP tools
- `view-events` — login and admin event tools

Do not use the `master` realm or grant `realm-admin` unless explicitly required.

## Run

### Stdio mode (default)

```sh
export KEYCLOAK_URL=https://keycloak.example.com
export KEYCLOAK_REALM=example
export KEYCLOAK_CLIENT_ID=gocloak-mcp
export KEYCLOAK_CLIENT_SECRET='<injected by your secret manager>'
go run ./cmd/keycloak-mcp
```

### Streamable HTTP mode

```sh
export MCP_TRANSPORT=http
export MCP_HTTP_ADDR=127.0.0.1:8080
export MCP_HTTP_BEARER_TOKEN='<at least 32 random chars for non-loopback>'
go run ./cmd/keycloak-mcp
```

Exposes `/mcp` (Streamable HTTP MCP endpoint) and `/healthz` (liveness probe).

## Read-Only Tools (32)

All tools declare `readOnlyHint: true`, `idempotentHint: true`, and
`destructiveHint: false`, accept an optional `realm` parameter checked against
`KEYCLOAK_ALLOWED_REALMS`, cap pagination at `max <= 100` (default `50`), and
return safe allowlist DTOs (never exposing credentials, client secrets, IdP
config secrets, or raw admin-event payloads).

- **Users:** `list_users`, `get_user`, `count_users`, `get_user_sessions`, `get_user_groups`, `get_user_roles`
- **Clients & Scopes:** `list_clients`, `get_client`, `get_client_service_account`, `list_client_roles`, `list_client_scopes`, `get_client_scope`
- **Roles:** `list_realm_roles`, `get_realm_role`, `get_users_in_role`, `get_users_in_client_role`
- **Groups:** `list_groups`, `count_groups`, `get_group`, `get_group_members`, `get_group_roles`
- **Realms & Events:** `list_realms`, `get_realm_info`, `list_events`, `list_admin_events`
- **Auth Flows & Required Actions:** `list_authentication_flows`, `get_flow_executions`, `list_required_actions`
- **Identity Providers:** `list_identity_providers`, `get_identity_provider`
- **Organizations (Keycloak 26+):** `list_organizations`, `get_organization_members`

## Build and verification

```sh
make check
```

## Container

```sh
docker build -t gocloak-mcp .
```

The image contains a static binary on `gcr.io/distroless/static-debian12:nonroot`.
