# Security

- Least privilege and read-only by default: only implement read-only Keycloak tools. Never expose destructive operations or master-admin defaults.
- Never log access tokens, client secrets, passwords, or PII.
- Sanitize errors returned to MCP clients; never leak internal stack traces, raw Keycloak HTTP bodies, or tokens.
- Load configuration strictly from environment variables and validate all inputs on startup.
- For Stdio transport, stdout is strictly reserved for MCP JSON-RPC frames. All structured logging (`log/slog`) MUST write to stderr only.
- Ban `fmt.Print*` across the codebase via linter rules (`forbidigo`).
- Strictly validate all MCP tool inputs: validate realm names, cap page sizes at 100, and reject negative offsets.
- Pin all GitHub Actions to full commit SHAs with version comments. Use minimal `permissions:` blocks in every GitHub Actions workflow (`contents: read` by default).
- Run `govulncheck ./...` and `gosec` in CI and fail on any finding.

# Performance

- Implement a thread-safe token provider using `sync.RWMutex` and `golang.org/x/sync/singleflight` so concurrent MCP requests never trigger duplicate Keycloak token requests.
- Refresh tokens proactively (30 seconds before expiry, or at 50% TTL for short-lived tokens).
- Configure the underlying HTTP transport with sensible timeouts (`DialContext`, `TLSHandshakeTimeout`, `IdleConnTimeout`, `MaxIdleConnsPerHost`) and enforce per-request `context.Context` timeouts.
- Preallocate slices when lengths are known (`make([]T, 0, len(src))`).
- Avoid unnecessary reflection, string concatenation in loops, or unbounded result sets.

# IOSP and clean code

- Every function or method MUST be either an Operation, containing logic, transformations, validation, or external I/O and calling no other internal business/domain functions, or an Integration, orchestrating internal functions/methods and containing no business logic, complex conditionals, or logic-heavy loops.
- Never mix orchestration and logic in the same function.
- Keep functions small, cohesive, and single-purpose.
- Use explicit dependency injection via interfaces defined on the consumer side so handlers and services are unit-testable without a live Keycloak instance.

# Linting

- Enable `gosec`, `errcheck`, `errorlint`, `nilerr`, `nilnil`, `bodyclose`, `noctx`, `sqlclosecheck`, `staticcheck`, `govet` (with `shadow`), `exhaustive`, and `copyloopvar`.
- Enable `prealloc`, `perfsprint`, and `makezero`.
- Enable `revive`, `gocritic` (diagnostic, performance, and style), `cyclop` (maximum complexity 10), `funlen` (maximum 50 lines and 30 statements), `nestif` (maximum nesting 3), `wrapcheck`, `unparam`, `unused`, `misspell`, `gofumpt`, and `goimports`.
- Forbid `fmt.Print`, `fmt.Printf`, and `fmt.Println` outside tests.
- Set `max-issues-per-linter: 0` and `max-same-issues: 0`.
