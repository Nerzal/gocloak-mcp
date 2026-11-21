#!/usr/bin/env python3
"""Reproducible head-to-head benchmark harness for Keycloak MCP servers.

Runs a local mock Keycloak Admin API server on 127.0.0.1 and benchmarks
gocloak-mcp (Go) against competing Keycloak MCP servers across Stdio and
Streamable HTTP transports under identical conditions.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import http.client
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def make_mock_jwt() -> str:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps(
            {
                "sub": "bench-service-account",
                "iss": "http://127.0.0.1/realms/example",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "preferred_username": "service-account-gocloak-mcp",
            }
        ).encode()
    ).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"mock-signature-for-local-benchmark").rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


MOCK_USERS = [
    {
        "id": f"00000000-0000-4000-8000-{i:012d}",
        "username": f"user-{i:03d}",
        "email": f"user-{i:03d}@example.test",
        "firstName": f"First{i}",
        "lastName": f"Last{i}",
        "enabled": True,
        "emailVerified": True,
        "createdTimestamp": 1700000000000 + i * 1000,
    }
    for i in range(50)
]
MOCK_USERS_BYTES = json.dumps(MOCK_USERS).encode()
MOCK_REALMS_BYTES = json.dumps([{"id": "example", "realm": "example", "enabled": True}]).encode()
MOCK_REALM_BYTES = json.dumps({"id": "example", "realm": "example", "enabled": True}).encode()


class MockKeycloakHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            _ = self.rfile.read(length)
        if "/protocol/openid-connect/token" in self.path:
            token_resp = json.dumps(
                {
                    "access_token": make_mock_jwt(),
                    "expires_in": 3600,
                    "refresh_expires_in": 3600,
                    "token_type": "Bearer",
                    "not-before-policy": 0,
                    "scope": "profile email",
                }
            ).encode()
            self._send_json(token_resp)
            return
        self._send_json(b"{}", status=200)

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path.endswith("/users"):
            self._send_json(MOCK_USERS_BYTES)
            return
        if path.endswith("/users/count"):
            self._send_json(str(len(MOCK_USERS)).encode())
            return
        if path.rstrip("/").endswith("/admin/realms"):
            self._send_json(MOCK_REALMS_BYTES)
            return
        if "/admin/realms/" in path:
            self._send_json(MOCK_REALM_BYTES)
            return
        if path.endswith("/.well-known/openid-configuration"):
            host = self.headers.get("Host", "127.0.0.1")
            issuer = f"http://{host}/realms/example"
            body = json.dumps(
                {
                    "issuer": issuer,
                    "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
                }
            ).encode()
            self._send_json(body)
            return
        if path.endswith("/certs"):
            self._send_json(b'{"keys":[]}')
            return
        self._send_json(b"[]")


def start_mock_keycloak() -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockKeycloakHandler)
    server.daemon_threads = True
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def read_rss_mb(pid: int) -> float:
    """Read VmRSS (MB) for pid and any direct children on Linux."""
    pids = [pid]
    try:
        children_path = Path(f"/proc/{pid}/task/{pid}/children")
        if children_path.exists():
            for child in children_path.read_text().split():
                if child.isdigit():
                    pids.append(int(child))
    except OSError:
        pass
    total_kb = 0
    for p in pids:
        try:
            for line in Path(f"/proc/{p}/status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total_kb += int(line.split()[1])
                    break
        except OSError:
            pass
    return round(total_kb / 1024.0, 1)


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(ordered) - 1)
    if f == c:
        return ordered[f]
    return ordered[f] + (ordered[c] - ordered[f]) * (k - f)


def stdio_send_and_recv(
    proc: subprocess.Popen[bytes], payload: dict[str, Any], timeout: float = 30.0
) -> dict[str, Any]:
    assert proc.stdin is not None and proc.stdout is not None
    req_id = payload.get("id")
    line = (json.dumps(payload) + "\n").encode()
    proc.stdin.write(line)
    proc.stdin.flush()

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = proc.stdout.readline()
        if not raw:
            stderr_tail = ""
            if proc.stderr is not None:
                try:
                    stderr_tail = proc.stderr.read().decode(errors="replace")[-500:]
                except Exception:
                    pass
            raise RuntimeError(f"EOF on stdout while waiting for id={req_id}; stderr={stderr_tail}")
        raw = raw.strip()
        if not raw.startswith(b"{"):
            continue
        msg = json.loads(raw)
        if msg.get("id") == req_id:
            return msg
    raise TimeoutError(f"Timed out waiting for stdio response id={req_id}")


def stdio_init(proc: subprocess.Popen[bytes]) -> None:
    assert proc.stdin is not None
    resp = stdio_send_and_recv(
        proc,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "gocloak-mcp-bench", "version": "1.0.0"},
            },
        },
    )
    if "error" in resp:
        raise RuntimeError(f"initialize failed: {resp}")
    proc.stdin.write(
        (json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n").encode()
    )
    proc.stdin.flush()
    tools_resp = stdio_send_and_recv(
        proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    )
    if "error" in tools_resp:
        raise RuntimeError(f"tools/list failed: {tools_resp}")


def benchmark_stdio_target(
    name: str,
    cmd: list[str],
    env: dict[str, str],
    tool_name: str,
    tool_args: dict[str, Any],
    cold_runs: int,
    warmup: int,
    iterations: int,
) -> dict[str, Any]:
    full_env = os.environ.copy()
    full_env.update(env)

    # 1. Cold start (median of cold_runs fresh spawns to initialize + tools/list)
    cold_ms: list[float] = []
    for _ in range(cold_runs):
        t0 = time.perf_counter()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=full_env,
        )
        try:
            stdio_init(proc)
            cold_ms.append((time.perf_counter() - t0) * 1000.0)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    # 2. Steady-state latency, throughput, and RSS
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=full_env,
    )
    try:
        stdio_init(proc)
        rss_idle = read_rss_mb(proc.pid)

        req_id = 10
        for _ in range(warmup):
            resp = stdio_send_and_recv(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": tool_args},
                },
            )
            req_id += 1
            if "error" in resp or resp.get("result", {}).get("isError"):
                raise RuntimeError(f"{name} warmup call failed: {resp}")

        latencies_ms: list[float] = []
        t_start = time.perf_counter()
        for _ in range(iterations):
            t0 = time.perf_counter()
            resp = stdio_send_and_recv(
                proc,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": tool_args},
                },
            )
            latencies_ms.append((time.perf_counter() - t0) * 1000.0)
            req_id += 1
            if "error" in resp or resp.get("result", {}).get("isError"):
                raise RuntimeError(f"{name} benchmark call failed: {resp}")
        total_s = time.perf_counter() - t_start
        rss_load = read_rss_mb(proc.pid)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    return {
        "name": name,
        "transport": "stdio",
        "cold_start_ms": round(statistics.median(cold_ms), 1),
        "rss_idle_mb": rss_idle,
        "rss_load_mb": rss_load,
        "p50_ms": round(percentile(latencies_ms, 50), 2),
        "p95_ms": round(percentile(latencies_ms, 95), 2),
        "p99_ms": round(percentile(latencies_ms, 99), 2),
        "rps": round(iterations / total_s, 1),
    }


def parse_mcp_http_body(body: bytes, content_type: str) -> dict[str, Any]:
    text = body.decode("utf-8", errors="replace").strip()
    if "text/event-stream" in content_type or text.startswith("event:") or text.startswith("data:"):
        for line in text.splitlines():
            if line.startswith("data:"):
                data = line[5:].strip()
                if data.startswith("{"):
                    return json.loads(data)
        raise RuntimeError(f"No JSON data line in SSE body: {text[:300]}")
    if not text:
        return {}
    return json.loads(text)


def http_post_mcp(
    host: str,
    port: int,
    path: str,
    payload: dict[str, Any],
    session_id: str | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict[str, str], dict[str, Any]]:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        conn.request("POST", path, body=json.dumps(payload).encode(), headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        parsed = (
            parse_mcp_http_body(body, resp_headers.get("content-type", ""))
            if resp.status < 300 and body
            else {"_raw": body.decode("utf-8", errors="replace")[:300]}
        )
        return resp.status, resp_headers, parsed
    finally:
        conn.close()


def http_init_session(host: str, port: int, path: str) -> str | None:
    status, headers, parsed = http_post_mcp(
        host,
        port,
        path,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "gocloak-mcp-bench", "version": "1.0.0"},
            },
        },
    )
    if status >= 300 or "error" in parsed:
        raise RuntimeError(f"HTTP initialize failed (status={status}): {parsed}")
    session_id = headers.get("mcp-session-id")
    http_post_mcp(
        host,
        port,
        path,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        session_id=session_id,
    )
    return session_id


def wait_for_http_mcp(
    proc: subprocess.Popen[bytes], host: str, port: int, path: str, timeout: float = 30.0
) -> tuple[float, str | None]:
    t0 = time.perf_counter()
    deadline = t0 + timeout
    last_err = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stderr_txt = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            raise RuntimeError(f"Server exited early ({proc.returncode}): {stderr_txt[-500:]}")
        try:
            session_id = http_init_session(host, port, path)
            return (time.perf_counter() - t0) * 1000.0, session_id
        except Exception as exc:
            last_err = str(exc)
            time.sleep(0.02)
    raise TimeoutError(f"HTTP server not ready on {host}:{port}{path}: {last_err}")


def benchmark_http_target(
    name: str,
    cmd: list[str],
    env: dict[str, str],
    port: int,
    path: str,
    tool_name: str,
    tool_args: dict[str, Any],
    cold_runs: int,
    warmup: int,
    iterations: int,
    concurrency: int,
) -> dict[str, Any]:
    full_env = os.environ.copy()
    full_env.update(env)
    host = "127.0.0.1"

    # 1. Cold start to ready HTTP MCP initialize
    cold_ms: list[float] = []
    for _ in range(cold_runs):
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=full_env
        )
        try:
            elapsed, _ = wait_for_http_mcp(proc, host, port, path)
            cold_ms.append(elapsed)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    # 2. Steady-state concurrent throughput, latency, and RSS
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=full_env)
    try:
        _, session_id = wait_for_http_mcp(proc, host, port, path)
        rss_idle = read_rss_mb(proc.pid)

        def call_once(req_id: int) -> float:
            t0 = time.perf_counter()
            status, _, parsed = http_post_mcp(
                host,
                port,
                path,
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": tool_args},
                },
                session_id=session_id,
            )
            dt = (time.perf_counter() - t0) * 1000.0
            if status >= 300 or "error" in parsed or parsed.get("result", {}).get("isError"):
                raise RuntimeError(f"{name} HTTP call failed (status={status}): {parsed}")
            return dt

        for i in range(warmup):
            call_once(100 + i)

        t_start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            latencies_ms = list(pool.map(call_once, range(1000, 1000 + iterations)))
        total_s = time.perf_counter() - t_start
        rss_load = read_rss_mb(proc.pid)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    return {
        "name": name,
        "transport": "http",
        "cold_start_ms": round(statistics.median(cold_ms), 1),
        "rss_idle_mb": rss_idle,
        "rss_load_mb": rss_load,
        "p50_ms": round(percentile(latencies_ms, 50), 2),
        "p95_ms": round(percentile(latencies_ms, 95), 2),
        "p99_ms": round(percentile(latencies_ms, 99), 2),
        "rps": round(iterations / total_s, 1),
    }


def file_size_mb(path: str | None) -> float | None:
    if not path or not os.path.exists(path):
        return None
    return round(os.path.getsize(path) / (1024 * 1024), 1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Head-to-head Keycloak MCP server benchmark")
    parser.add_argument("--gocloak-bin", required=True, help="Path to gocloak-mcp binary")
    parser.add_argument("--haitham-entry", help="Path to HaithamOumerzoug/keycloak-mcp dist/server.js")
    parser.add_argument("--idoyudha-bin", help="Path to idoyudha/mcp-keycloak executable")
    parser.add_argument("--sshaaf-native", help="Path to sshaaf/keycloak-mcp-server native binary")
    parser.add_argument("--sshaaf-jar", help="Path to sshaaf/keycloak-mcp-server runner jar")
    parser.add_argument("--out", default="benchmark-results.json", help="Output JSON file")
    args = parser.parse_args()

    mock_server, kc_port = start_mock_keycloak()
    kc_url = f"http://127.0.0.1:{kc_port}"
    print(f"Mock Keycloak listening on {kc_url}", file=sys.stderr)

    results: list[dict[str, Any]] = []

    try:
        # --- STDIO BENCHMARKS ---
        gocloak_env = {
            "KEYCLOAK_URL": kc_url,
            "KEYCLOAK_REALM": "example",
            "KEYCLOAK_CLIENT_ID": "gocloak-mcp",
            "KEYCLOAK_CLIENT_SECRET": "benchmark-secret-value",
        }
        res = benchmark_stdio_target(
            name="gocloak-mcp (Go)",
            cmd=[args.gocloak_bin],
            env=gocloak_env,
            tool_name="list_users",
            tool_args={"max": 50},
            cold_runs=5,
            warmup=10,
            iterations=100,
        )
        res["binary_mb"] = file_size_mb(args.gocloak_bin)
        results.append(res)
        print(f"[DONE] {res}", file=sys.stderr)

        if args.haitham_entry and os.path.exists(args.haitham_entry):
            try:
                res = benchmark_stdio_target(
                    name="HaithamOumerzoug/keycloak-mcp (TypeScript/Node)",
                    cmd=[shutil.which("node") or "node", args.haitham_entry],
                    env={
                        "KEYCLOAK_URL": kc_url,
                        "KEYCLOAK_ADMIN": "admin",
                        "KEYCLOAK_ADMIN_PASSWORD": "admin",
                    },
                    tool_name="list-users",
                    tool_args={"realm": "example"},
                    cold_runs=5,
                    warmup=10,
                    iterations=100,
                )
                results.append(res)
                print(f"[DONE] {res}", file=sys.stderr)
            except Exception as exc:
                print(f"[WARN] HaithamOumerzoug stdio failed: {exc}", file=sys.stderr)

        if args.idoyudha_bin and os.path.exists(args.idoyudha_bin):
            try:
                res = benchmark_stdio_target(
                    name="idoyudha/mcp-keycloak (Python/FastMCP)",
                    cmd=[args.idoyudha_bin],
                    env={
                        "SERVER_URL": kc_url,
                        "REALM_NAME": "example",
                        "CLIENT_ID": "gocloak-mcp",
                        "CLIENT_SECRET": "benchmark-secret-value",
                        "USERNAME": "admin",
                        "PASSWORD": "admin",
                        "TRANSPORT": "stdio",
                    },
                    tool_name="list_users",
                    tool_args={"max": 50},
                    cold_runs=5,
                    warmup=10,
                    iterations=100,
                )
                results.append(res)
                print(f"[DONE] {res}", file=sys.stderr)
            except Exception as exc:
                print(f"[WARN] idoyudha stdio failed: {exc}", file=sys.stderr)

        # --- STREAMABLE HTTP BENCHMARKS ---
        go_http_port = find_free_port()
        res = benchmark_http_target(
            name="gocloak-mcp (Go)",
            cmd=[args.gocloak_bin],
            env={
                **gocloak_env,
                "MCP_TRANSPORT": "http",
                "MCP_HTTP_ADDR": f"127.0.0.1:{go_http_port}",
            },
            port=go_http_port,
            path="/mcp",
            tool_name="list_users",
            tool_args={"max": 50},
            cold_runs=3,
            warmup=20,
            iterations=300,
            concurrency=10,
        )
        res["binary_mb"] = file_size_mb(args.gocloak_bin)
        results.append(res)
        print(f"[DONE] {res}", file=sys.stderr)

        if args.sshaaf_native and os.path.exists(args.sshaaf_native):
            try:
                port = find_free_port()
                res = benchmark_http_target(
                    name="sshaaf/keycloak-mcp-server (Java/Quarkus Native)",
                    cmd=[args.sshaaf_native],
                    env={
                        "KC_URL": kc_url,
                        "KC_REALM": "example",
                        "QUARKUS_HTTP_PORT": str(port),
                        "QUARKUS_OIDC_ENABLED": "false",
                        "QUARKUS_HTTP_AUTH_PERMISSION_MCP_POLICY": "permit",
                        "KC_DEV_USER": "admin",
                        "KC_DEV_PASSWORD": "admin",
                    },
                    port=port,
                    path="/mcp",
                    tool_name="executeKeycloakOperation",
                    tool_args={"operation": "GET_USERS", "params": '{"realm":"example"}'},
                    cold_runs=3,
                    warmup=20,
                    iterations=300,
                    concurrency=10,
                )
                res["binary_mb"] = file_size_mb(args.sshaaf_native)
                results.append(res)
                print(f"[DONE] {res}", file=sys.stderr)
            except Exception as exc:
                print(f"[WARN] sshaaf native HTTP failed: {exc}", file=sys.stderr)

        if args.sshaaf_jar and os.path.exists(args.sshaaf_jar):
            try:
                port = find_free_port()
                res = benchmark_http_target(
                    name="sshaaf/keycloak-mcp-server (Java/Quarkus JVM)",
                    cmd=[shutil.which("java") or "java", "-jar", args.sshaaf_jar],
                    env={
                        "KC_URL": kc_url,
                        "KC_REALM": "example",
                        "QUARKUS_HTTP_PORT": str(port),
                        "QUARKUS_OIDC_ENABLED": "false",
                        "QUARKUS_HTTP_AUTH_PERMISSION_MCP_POLICY": "permit",
                        "KC_DEV_USER": "admin",
                        "KC_DEV_PASSWORD": "admin",
                    },
                    port=port,
                    path="/mcp",
                    tool_name="executeKeycloakOperation",
                    tool_args={"operation": "GET_USERS", "params": '{"realm":"example"}'},
                    cold_runs=3,
                    warmup=20,
                    iterations=300,
                    concurrency=10,
                )
                res["binary_mb"] = file_size_mb(args.sshaaf_jar)
                results.append(res)
                print(f"[DONE] {res}", file=sys.stderr)
            except Exception as exc:
                print(f"[WARN] sshaaf JVM HTTP failed: {exc}", file=sys.stderr)

        if args.idoyudha_bin and os.path.exists(args.idoyudha_bin):
            try:
                port = find_free_port()
                res = benchmark_http_target(
                    name="idoyudha/mcp-keycloak (Python/FastMCP HTTP)",
                    cmd=[args.idoyudha_bin],
                    env={
                        "SERVER_URL": kc_url,
                        "REALM_NAME": "example",
                        "CLIENT_ID": "gocloak-mcp",
                        "CLIENT_SECRET": "benchmark-secret-value",
                        "USERNAME": "admin",
                        "PASSWORD": "admin",
                        "TRANSPORT": "http",
                        "PORT": str(port),
                    },
                    port=port,
                    path="/mcp/",
                    tool_name="list_users",
                    tool_args={"max": 50},
                    cold_runs=3,
                    warmup=20,
                    iterations=300,
                    concurrency=10,
                )
                results.append(res)
                print(f"[DONE] {res}", file=sys.stderr)
            except Exception as exc:
                print(f"[WARN] idoyudha HTTP failed: {exc}", file=sys.stderr)
    finally:
        mock_server.shutdown()

    report = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "results": results,
    }
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n")

    print("\n## Head-to-Head Benchmark Results\n")
    for transport in ("stdio", "http"):
        rows = [r for r in results if r["transport"] == transport]
        if not rows:
            continue
        print(f"### Transport: `{transport}`\n")
        print("| Server | Binary (MB) | Cold Start (ms) | RSS Idle (MB) | RSS Load (MB) | p50 (ms) | p95 (ms) | p99 (ms) | Throughput (req/s) |")
        print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for r in rows:
            bm = f"{r['binary_mb']}" if r.get("binary_mb") is not None else "—"
            print(
                f"| {r['name']} | {bm} | {r['cold_start_ms']} | {r['rss_idle_mb']} | "
                f"{r['rss_load_mb']} | {r['p50_ms']} | {r['p95_ms']} | {r['p99_ms']} | {r['rps']} |"
            )
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
