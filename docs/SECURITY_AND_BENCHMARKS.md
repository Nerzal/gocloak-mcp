# Security (OWASP MCP Top 10) & Performance Benchmarks

## 1. OWASP MCP Top 10 (2025) Control & Test Matrix

Based on the [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10) specification:

| Risk | Controls in `gocloak-mcp` | Automated Test Coverage |
| --- | --- | --- |
| **MCP01:2025 — Token Mismanagement & Secret Exposure** | Env-only credentials (fail-fast); `Config.String()` & `Config.LogValue()` redact `ClientSecret` & `HTTPBearerToken`; HTTP redirects disabled (blocks HTTPS→HTTP Basic-Auth leakage); allowlist DTOs omit `Client.Secret`, `IdP.Config`, `User.Credentials`, `AdminEvent.Representation`; `slog` redacts sensitive keys, nested groups, and `Bearer `/JWT values; sanitized tool errors. | `TestOWASP_MCP01_SecretExposureBlockedInDTOs`, `TestOWASP_MCP01_ToolErrorsNeverLeakTokensOrBodies`, `TestConfigRedactsSecretsInStringAndLogValue`, `TestRedactAttributeRedactsJWTAndBearerValues`, `TestNewKeycloakClientBlocksRedirects` |
| **MCP02:2025 — Privilege Escalation via Scope Creep** | Strictly read-only (32 tools, zero write/delete/password-reset/secret-read tools); `KEYCLOAK_ALLOWED_REALMS` allowlist enforced on every call and filters `list_realms`; minimal Keycloak service-account roles documented. | `TestOWASP_MCP02_ScopeCreepRealmAllowlistEnforced`, `TestOWASP_MCP02_MCP03_ToolCatalogIntegrityAndNoPoisoning` |
| **MCP03:2025 — Tool Poisoning** | Static compile-time tool catalog (no dynamic plugin loading or remote schema injection); all tools explicitly declare `readOnlyHint: true`, `idempotentHint: true`, `destructiveHint: false`. | `TestOWASP_MCP02_MCP03_ToolCatalogIntegrityAndNoPoisoning`, `TestAll32ReadOnlyToolsRegisteredAndCallable` |
| **MCP04:2025 — Software Supply Chain Attacks** | Minimal direct dependencies (`gocloak/v15`, `modelcontextprotocol/go-sdk`, `x/sync`); `govulncheck`, `gosec`, `golangci-lint`, CodeQL in CI; pinned GitHub Actions commit SHAs; `go mod verify` + static distroless `nonroot` container; Dependabot enabled. | CI `verify` (`govulncheck`, `gosec`, `docker build`) & `CodeQL` |
| **MCP05:2025 — Command Injection & Execution** | Zero `os/exec` or shell calls; strict `validateIdentifier` rejects `/`, `\`, `?`, `#`, `%` (URL-encoded traversal), `.`, `..`, control chars, untrimmed whitespace, and >255 chars; strict `YYYY-MM-DD` date validation. | `TestOWASP_MCP05_PathTraversalAndInjectionRejected` |
| **MCP06:2025 — Prompt Injection via Contextual Payloads** | `sanitizeOutputString` strips ASCII control chars (ANSI escapes, NUL) and Unicode BiDi overrides (`U+202A..U+202E`, `U+2066..U+2069`) and caps free-text fields at 512 runes with zero allocations on clean strings. | `TestOWASP_MCP06_OutputSanitizationNeutralizesControlAndBiDiRunes` |
| **MCP07:2025 — Insufficient Authentication & Authorization** | Streamable HTTP defaults to loopback (`127.0.0.1:8080`); non-loopback binds **require** `MCP_HTTP_BEARER_TOKEN` (≥32 chars) verified with `crypto/subtle.ConstantTimeCompare`; `Origin` header validation blocks DNS rebinding (`403 Forbidden`); security headers (`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `X-Frame-Options: DENY`). | `TestOWASP_MCP07_HTTPAuthAndOriginProtection`, `TestNewHTTPServerBearerAuth`, `TestNewHTTPServerOriginValidationPreventsDNSRebinding`, `TestLoadHTTPTransportLoopbackAndNonLoopback` |
| **MCP08:2025 — Lack of Audit and Telemetry** | Every tool call emits a structured JSON audit record on `stderr` (`tool`, `outcome`, `duration_ms`) without PII or secrets. | `TestOWASP_MCP08_StructuredAuditLoggingOnSuccessAndError` |
| **MCP09:2025 — Shadow MCP Servers** | No default credentials; fail-fast startup validation; loopback-only default for HTTP; `/healthz` liveness probe for fleet inventory. | `TestLoadRejectsInvalidConfiguration`, `TestNewHTTPServerHealthzAndSecurityHeaders` |
| **MCP10:2025 — Context Injection & Over-Sharing** | Stateless per-request handling (no cross-session user data caching); bounded pagination (`max <= 100`, explicit `max: 0` rejected); strict realm allowlisting. | `TestOWASP_MCP10_BoundedPaginationPreventsContextOverSharing` |

---

## 2. Go Micro-Benchmarks (`gocloak-mcp`)

Run locally with:

```sh
make bench
```

Measured on `linux/amd64` (Intel Xeon Platinum 8481C, Go 1.27):

| Benchmark | Latency | Memory / op | Allocs / op |
| --- | ---: | ---: | ---: |
| `BenchmarkRedactAttributeBuiltin` | **17.1 ns/op** | 0 B/op | **0** |
| `BenchmarkRedactAttributeSensitive` | **35.8 ns/op** | 0 B/op | **0** |
| `BenchmarkValidateIdentifier` | **53.7 ns/op** | 0 B/op | **0** |
| `BenchmarkTokenProviderCachedHit` | **78.9 ns/op** | 0 B/op | **0** |
| `BenchmarkTokenProviderCachedHitParallel` | **91.0 ns/op** | 0 B/op | **0** |
| `BenchmarkSanitizeOutputStringClean` | **108.9 ns/op** | 0 B/op | **0** |
| `BenchmarkRedactAttributeSafe` | **131.3 ns/op** | 0 B/op | **0** |
| `BenchmarkListUsers100` (full 100-user service pipeline) | **18.1 µs/op** | 9.5 KB/op | **6** |

End-to-end MCP JSON-RPC (`BenchmarkInMemoryMCPCallListUsers`) and Streamable HTTP security middleware (`BenchmarkHTTPMiddlewareChain`) benchmarks also run automatically on every CI build.

---

## 3. Head-to-Head Comparison vs. Competing Keycloak MCP Servers

All servers were benchmarked head-to-head on the same machine (`ubuntu-latest`, 4 vCPU `x86_64`, Linux 7.0) against an identical local mock Keycloak Admin API returning 50 users per `list_users` call. The benchmark harness is fully reproducible in [`benchmarks/run_benchmarks.py`](../benchmarks/run_benchmarks.py) and automated via [`.github/workflows/benchmark.yml`](../.github/workflows/benchmark.yml) (`workflow_dispatch`).

### Stdio Transport (Local IDE / Agent: Claude Desktop, Cursor, VS Code, Claude Code)

Measured across 5 cold starts (`initialize` + `tools/list`) and 100 sequential `tools/call` (`list_users` / `list-users`) requests after 10 warm-up calls:

| Server | Runtime / Binary | Cold Start (median) | RSS Idle → Load | p50 Latency | p95 Latency | p99 Latency | Throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **`gocloak-mcp` (`v0.2.0`, Go)** | **10.0 MB static binary** | **12.2 ms** | **15.3 → 16.3 MB** | **1.06 ms** | **1.30 ms** | **1.47 ms** | **954.7 req/s** |
| [`HaithamOumerzoug/keycloak-mcp`](https://github.com/HaithamOumerzoug/keycloak-mcp) (`1.2.5`, TypeScript/Node 22) | Node.js 22 + `node_modules` | 68.5 ms *(5.6×)* | 64.1 → 88.7 MB *(5.4×)* | 1.23 ms | 2.20 ms | 2.42 ms | 728.2 req/s |
| [`idoyudha/mcp-keycloak`](https://github.com/idoyudha/mcp-keycloak) (`v1.2.2`, Python 3.12/FastMCP) | Python 3.12 + venv | 359.3 ms *(29.5×)* | 61.0 → 64.2 MB *(3.9×)* | 3.66 ms | 3.92 ms | 4.01 ms | 271.5 req/s *(3.5× slower)* |

### Streamable HTTP Transport (Remote / Kubernetes / Server)

Measured across 3 cold starts to ready `/mcp` `initialize` and 300 concurrent `tools/call` (`list_users` / `GET_USERS`) requests at concurrency 10 after 20 warm-up calls:

| Server | Binary / OCI Image | Cold Start (median) | RSS Idle → Load | p50 Latency | p95 Latency | p99 Latency | Throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **`gocloak-mcp` (`v0.2.0`, Go)** | **10.0 MB / 21.4 MB** | **21.8 ms** | **14.4 → 19.5 MB** | **7.46 ms** | **13.13 ms** | **15.24 ms** | **1,194.9 req/s** |
| [`sshaaf/keycloak-mcp-server`](https://github.com/sshaaf/keycloak-mcp-server) (`v0.4.0`, Java/Quarkus Native) | 74.1 MB binary | 43.2 ms *(2.0×)* | 71.6 → 158.8 MB *(8.1×)* | 9.83 ms | 22.21 ms | 27.77 ms | 214.1 req/s *(5.6× slower)* |
| [`sshaaf/keycloak-mcp-server`](https://github.com/sshaaf/keycloak-mcp-server) (`v0.4.0`, Java/Quarkus JVM) | 23.4 MB JAR / 626 MB img | 1,249.8 ms *(57.3×)* | 196.7 → 319.9 MB *(16.4×)* | 35.60 ms | 72.44 ms | 92.31 ms | 251.8 req/s *(4.7× slower)* |

### Security & Operational Footprint Comparison

| Capability | `gocloak-mcp` (Go) | `sshaaf/keycloak-mcp-server` (Java) | `HaithamOumerzoug/keycloak-mcp` (TS) | `idoyudha/mcp-keycloak` (Python) |
| --- | --- | --- | --- | --- |
| **Transports** | **Stdio + Streamable HTTP** | Streamable HTTP / SSE | Stdio | Stdio + HTTP |
| **Default Access Model** | **Strictly read-only (32 tools)** | Read + Write (178 ops) | Read + Write/Delete | Read + Write/Delete |
| **Auth Model** | **OAuth2 Client Credentials (least-privilege service account)** | User JWT / OIDC | Master admin username + password | Username + password / client secret |
| **Multi-Realm Allowlist** | **Yes (`KEYCLOAK_ALLOWED_REALMS`)** | No | No | No |
| **OWASP MCP Top 10 Test Suite** | **Yes (10/10 automated)** | No | No | No |
| **OCI Image Size** | **21.4 MB (distroless nonroot)** | 626 MB (UBI9 OpenJDK 21) | — | — |
| **Distribution** | **GitHub Releases (6 platforms), Homebrew Cask, GHCR, MCP Registry** | GitHub Releases, Quay.io | npm / source | PyPI / source |

**Key takeaways:**
- **5.6× faster cold start** and **5.4× less RAM** than TypeScript/Node (`HaithamOumerzoug/keycloak-mcp`), and **29.5× faster cold start** / **3.5× higher throughput** than Python/FastMCP (`idoyudha/mcp-keycloak`) over Stdio.
- **5.6× higher HTTP throughput**, **8.1× less RAM**, and a **7.4× smaller binary** than Java/Quarkus GraalVM Native (`sshaaf/keycloak-mcp-server`), and **57× faster cold start**, **16.4× less RAM**, and a **29× smaller container image** (21.4 MB vs. 626 MB) than Quarkus JVM.
