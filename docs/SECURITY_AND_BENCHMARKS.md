# Security (OWASP MCP Top 10) & Performance Benchmarks

## 1. OWASP MCP Top 10 (2025) Control & Test Matrix

Based on the [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10) specification:

| Risk | Controls in `gocloak-mcp` | Automated Test Coverage |
| --- | --- | --- |
| **MCP01:2025 — Token Mismanagement & Secret Exposure** | Env-only credentials (fail-fast); `Config.String()` & `Config.LogValue()` redact `ClientSecret` & `HTTPBearerToken`; HTTP redirects disabled (blocks HTTPS→HTTP Basic-Auth leakage); allowlist DTOs omit `Client.Secret`, `IdP.Config`, `User.Credentials`, `AdminEvent.Representation`; `slog` redacts sensitive keys, nested groups, and `Bearer `/JWT values; sanitized tool errors. | `TestOWASP_MCP01_SecretExposureBlockedInDTOs`, `TestOWASP_MCP01_ToolErrorsNeverLeakTokensOrBodies`, `TestConfigRedactsSecretsInStringAndLogValue`, `TestRedactAttributeRedactsJWTAndBearerValues`, `TestNewKeycloakClientBlocksRedirects` |
| **MCP02:2025 — Privilege Escalation via Scope Creep** | Strictly read-only (32 tools, zero write/delete/password-reset/secret-read tools); `KEYCLOAK_ALLOWED_REALMS` allowlist enforced on every call and filters `list_realms`; minimal Keycloak service-account roles documented. | `TestOWASP_MCP02_ScopeCreepRealmAllowlistEnforced`, `TestOWASP_MCP02_MCP03_ToolCatalogIntegrityAndNoPoisoning` |
| **MCP03:2025 — Tool Poisoning** | Static compile-time tool catalog (no dynamic plugin loading or remote schema injection); all tools explicitly declare `readOnlyHint: true`, `idempotentHint: true`, `destructiveHint: false`. | `TestOWASP_MCP02_MCP03_ToolCatalogIntegrityAndNoPoisoning`, `TestAll32ReadOnlyToolsRegisteredAndCallable` |
| **MCP04:2025 — Software Supply Chain Attacks** | Minimal direct dependencies (`gocloak/v14`, `modelcontextprotocol/go-sdk`, `x/sync`); `govulncheck`, `gosec`, `golangci-lint`, CodeQL in CI; pinned GitHub Actions commit SHAs; `go mod verify` + static distroless `nonroot` container; Dependabot enabled. | CI `verify` (`govulncheck`, `gosec`, `docker build`) & `CodeQL` |
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

## 3. Comparison with Java & Python MCP Servers

In independent multi-language MCP server benchmarks (**TM Dev Lab 2026**, 3.9M requests across Go official SDK, Java Spring/Quarkus, Node.js, and Python FastMCP) and typical Keycloak MCP deployments:

| Dimension | `gocloak-mcp` (Go) | Java (Quarkus JVM / Spring) | Java (Quarkus Native) | Python (FastMCP) |
| --- | --- | --- | --- | --- |
| **Runtime & Distribution** | Single static binary (`CGO_ENABLED=0`, distroless ~15–20 MB) | JRE + JAR (~250–350 MB image) | Native binary (~80–120 MB, 3–5 min build) | CPython + venv (~150–250 MB image) |
| **Cold Start** | **~5–15 ms** | ~2–5 s (JVM warm-up) | ~50–100 ms | ~300–800 ms |
| **Idle / Steady Memory (RSS)** | **~15–25 MB** | ~195–230 MB (~10–12× Go) | ~40–70 MB | ~60–100 MB |
| **Protocol Throughput (RPS)** | **~1,624 RPS** (0.86 ms avg) | ~1,624 RPS (0.84 ms avg) | ~1,400–1,600 RPS | ~292 RPS (26.5 ms avg — **~31× slower** latency) |
| **Build Time** | **~2–5 s** | ~30–60 s | ~3–5 min | N/A (interpreted) |

**Key takeaway:** Go matches Java's sub-millisecond MCP protocol latency and throughput (~5.5× higher RPS and ~30× lower latency than Python FastMCP) while using **~10× less RAM than JVM Java**, starting in milliseconds (critical for Stdio MCP servers spawned on-demand by IDEs/agents), and building in seconds into a minimal distroless static image.
