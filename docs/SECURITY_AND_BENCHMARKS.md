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

All servers were benchmarked head-to-head on the same machine (`ubuntu-latest`, 4 vCPU `x86_64`, Linux 7.0) against an identical local mock Keycloak Admin API returning 50 users per `list_users` call. The benchmark harness is fully reproducible in [`benchmarks/run_benchmarks.py`](../benchmarks/run_benchmarks.py) and runnable on demand via [`.github/workflows/benchmark.yml`](../.github/workflows/benchmark.yml) (`workflow_dispatch`).

### Stdio Transport (Local IDE / Agent: Claude Desktop, Cursor, VS Code, Claude Code)

Measured across 5 cold starts (`initialize` + `tools/list`) and 100 sequential `tools/call` (`list_users` / `list-users`) requests after 10 warm-up calls:

| Server | Runtime / Binary | Cold Start (median) | RSS Idle → Load | p50 Latency | p95 Latency | p99 Latency | Throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **`gocloak-mcp` (Go 1.27 + `json/v2`)** | **10.2 MB static binary** | **6.5 ms** | **13.7 → 16.4 MB** | **0.61 ms** | 0.96 ms | 1.05 ms | **1,524.5 req/s** |
| [`MnemoShare/mnemoshare-keycloak-mcp`](https://github.com/MnemoShare/mnemoshare-keycloak-mcp) (Go) | 10.4 MB static binary | 12.6 ms *(1.9×)* | 14.4 → 17.4 MB | 0.62 ms | **0.94 ms** | **1.00 ms** | 1,507.2 req/s |
| [`HaithamOumerzoug/keycloak-mcp`](https://github.com/HaithamOumerzoug/keycloak-mcp) (`1.2.5`, TypeScript/Node 22) | Node.js 22 + `node_modules` | 69.5 ms *(10.7×)* | 67.1 → 90.7 MB *(5.5×)* | 1.50 ms | 2.59 ms | 4.18 ms | 596.7 req/s *(2.6× slower)* |
| [`idoyudha/mcp-keycloak`](https://github.com/idoyudha/mcp-keycloak) (`v1.2.2`, Python 3.12/FastMCP) | Python 3.12 + venv | 381.9 ms *(58.8×)* | 61.0 → 64.2 MB *(3.9×)* | 4.88 ms | 5.04 ms | 5.13 ms | 215.9 req/s *(7.1× slower)* |

### Streamable HTTP Transport (Remote / Kubernetes / Server)

Measured across 3 cold starts to ready `/mcp` `initialize` and 300 concurrent `tools/call` (`list_users` / `GET_USERS`) requests at concurrency 10 after 20 warm-up calls:

| Server | Binary / OCI Image | Cold Start (median) | RSS Idle → Load | p50 Latency | p95 Latency | p99 Latency | Throughput |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **`gocloak-mcp` (Go 1.27 + `json/v2`)** | **10.2 MB / 21.1 MB** | 21.2 ms | **12.9 → 17.2 MB** | **5.21 ms** | **8.66 ms** | **10.15 ms** | 1,640.4 req/s |
| [`MnemoShare/mnemoshare-keycloak-mcp`](https://github.com/MnemoShare/mnemoshare-keycloak-mcp) (Go) | 10.4 MB binary | **21.0 ms** | 14.0 → 19.5 MB | 5.39 ms | 8.91 ms | 10.40 ms | **1,710.1 req/s** |
| [`sshaaf/keycloak-mcp-server`](https://github.com/sshaaf/keycloak-mcp-server) (`v0.4.0`, Java/Quarkus Native) | 74.1 MB binary | 42.1 ms *(2.0×)* | 71.6 → 160.5 MB *(9.3×)* | 9.77 ms | 22.45 ms | 39.28 ms | 227.7 req/s *(7.2× slower)* |
| [`sshaaf/keycloak-mcp-server`](https://github.com/sshaaf/keycloak-mcp-server) (`v0.4.0`, Java/Quarkus JVM) | 23.4 MB JAR / 626 MB img | 1,434.2 ms *(67.7×)* | 201.6 → 316.6 MB *(18.4×)* | 39.75 ms | 76.15 ms | 88.08 ms | 229.6 req/s *(7.1× slower)* |

### `pprof` Optimization Proof (Baseline → v1 → v2)

Saved CPU and heap profiles live in [`benchmarks/profiles/baseline/`](../benchmarks/profiles/baseline), [`benchmarks/profiles/optimized/`](../benchmarks/profiles/optimized), and [`benchmarks/profiles/optimized_v2/`](../benchmarks/profiles/optimized_v2):

| Benchmark | Baseline | Optimized v1 | **Optimized v2 (`json/v2` + `addFastTool`)** | Total Improvement |
| --- | ---: | ---: | ---: | ---: |
| `BenchmarkRedactAttributeSafe` | 131.3 ns/op | 131.3 ns/op | **17.1 ns/op (0 allocs)** | **7.7× faster** |
| `BenchmarkEndToEndHTTPListUsers50` (local `pprof`) | 1,224.7 µs · 628 KB · 5,480 allocs | 735.7 µs · 408 KB · 1,124 allocs | **641.1 µs · 338 KB · 1,064 allocs** | **-47.7% latency · -46.1% B/op · -80.6% allocs** |
| Head-to-Head Stdio (`ubuntu-latest`) | 15.0 ms cold · 692.9 req/s | 6.8 ms cold · 1,312.9 req/s | **6.5 ms cold · 1,524.5 req/s** | **2.3× faster cold start · +120.0% throughput** |
| Head-to-Head Streamable HTTP (`ubuntu-latest`) | 9.44 ms p50 · 956.6 req/s | 5.77 ms p50 · 1,593.3 req/s | **5.21 ms p50 · 1,640.4 req/s** | **-44.8% p50 · +71.5% throughput** |

Inspect the exact profile diff locally:

```sh
go tool pprof -top -cum -diff_base=benchmarks/profiles/baseline/e2e_http_cpu.prof benchmarks/profiles/optimized_v2/e2e_http_cpu.prof
go tool pprof -top -alloc_space -diff_base=benchmarks/profiles/baseline/e2e_http_mem.prof benchmarks/profiles/optimized_v2/e2e_http_mem.prof
```

### Security & Operational Footprint Comparison

| Capability | `gocloak-mcp` (Go) | `MnemoShare/mnemoshare-keycloak-mcp` (Go) | `sshaaf/keycloak-mcp-server` (Java) | `HaithamOumerzoug/keycloak-mcp` (TS) | `idoyudha/mcp-keycloak` (Python) |
| --- | --- | --- | --- | --- | --- |
| **Transports** | **Stdio + Streamable HTTP** | Stdio + Streamable HTTP | Streamable HTTP / SSE | Stdio | Stdio + HTTP |
| **Default Access Model** | **Strictly read-only (32 tools)** | Read + Write/Delete (134 tools) | Read + Write (178 ops) | Read + Write/Delete | Read + Write/Delete |
| **Auth Model** | **OAuth2 Client Credentials (least-privilege service account)** | Password or Client Credentials | User JWT / OIDC | Master admin username + password | Username + password / client secret |
| **HTTP Auth & Origin Protection** | **Bearer token (≥32 chars) + Origin allowlist + security headers** | None built-in | OIDC JWT | N/A | Origin check (no Bearer auth) |
| **Multi-Realm Allowlist** | **Yes (`KEYCLOAK_ALLOWED_REALMS`)** | No | No | No | No |
| **OWASP MCP Top 10 Test Suite** | **Yes (10/10 automated)** | No | No | No | No |
| **OCI Image Size** | **21.1 MB (distroless nonroot)** | — | 626 MB (UBI9 OpenJDK 21) | — | — |
| **Distribution** | **GitHub Releases (6 platforms), Homebrew Cask, GHCR, MCP Registry** | Source / Docker | GitHub Releases, Quay.io | npm / source | PyPI / source |

**Key takeaways:**
- **#1 overall on Stdio** — beats every competitor including Go (`MnemoShare`: **1.9× faster cold start**, higher throughput, lower RSS), TypeScript/Node (**10.7× faster cold start**, **5.5× less RAM**), and Python/FastMCP (**58.8× faster cold start**, **7.1× higher throughput**) while running allowlist DTO sanitization and structured audit logging on every call.
- **Streamable HTTP:** **#1 on p50 (5.21 ms), p95 (8.66 ms), p99 (10.15 ms) latency, and RSS (17.2 MB)** across all competitors including Go `MnemoShare`, and **7.2× higher throughput** / **9.3× less RAM** than Java/Quarkus Native (**29.7× smaller container image** than Quarkus JVM at 21.1 MB vs. 626 MB).
