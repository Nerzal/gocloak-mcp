# Security Policy

## Supported versions

Only the latest version on the default branch is currently supported.

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub's
[security advisory](https://github.com/Nerzal/gocloak-mcp/security/advisories/new)
reporting flow. Do not include live credentials or personal data in a report.

This server is read-only and designed for Stdio transport. Never send secrets,
access tokens, passwords, or personal data to logs or public issues. Use a
dedicated least-privilege Keycloak service account and keep its client secret in
a secret manager.
