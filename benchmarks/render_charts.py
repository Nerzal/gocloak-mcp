#!/usr/bin/env python3
"""Generate crisp, publication-grade SVG benchmark charts for README and docs."""

from __future__ import annotations

from html import escape
from pathlib import Path

OUT_DIR = Path("docs/assets")

# Color palette (GitHub-dark card theme that looks sharp on both light and dark GitHub UIs)
BG = "#0d1117"
CARD = "#161b22"
BORDER = "#30363d"
TEXT = "#f0f6fc"
MUTED = "#8b949e"
TRACK = "#21262d"
ACCENT = "#00d4aa"      # gocloak-mcp highlight (vibrant Go-teal)
ACCENT_2 = "#38bdf8"    # secondary highlight
COMP_GO = "#58a6ff"     # Go competitor
COMP_TS = "#f59e0b"     # TypeScript/Node
COMP_PY = "#a78bfa"     # Python
COMP_JAVA = "#f97316"   # Java Quarkus Native
COMP_JVM = "#ef4444"    # Java Quarkus JVM


def fmt_num(val: float, suffix: str = "") -> str:
    if val >= 1000:
        return f"{val:,.0f}{suffix}"
    if val >= 100:
        return f"{val:.0f}{suffix}"
    if val >= 10:
        return f"{val:.1f}{suffix}"
    return f"{val:.1f}{suffix}"


def render_bar_panel(
    x: int,
    y: int,
    w: int,
    h: int,
    title: str,
    subtitle: str,
    items: list[tuple[str, float, str, bool]],
    suffix: str,
    max_val: float | None = None,
) -> str:
    parts = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{CARD}" stroke="{BORDER}" stroke-width="1"/>',
        f'<text x="{x + 20}" y="{y + 30}" fill="{TEXT}" font-size="15" font-weight="700">{escape(title)}</text>',
        f'<text x="{x + 20}" y="{y + 48}" fill="{MUTED}" font-size="11.5">{escape(subtitle)}</text>',
    ]
    top_max = max_val if max_val is not None else max(v for _, v, _, _ in items)
    bar_x = x + 178
    bar_max_w = w - 275
    row_y = y + 76
    row_step = (h - 92) / max(len(items), 1)

    for label, value, color, highlight in items:
        bw = max(6.0, (value / top_max) * bar_max_w)
        font_w = "700" if highlight else "500"
        label_fill = ACCENT if highlight else TEXT
        val_fill = ACCENT if highlight else TEXT
        cy = row_y + 12

        parts.append(
            f'<text x="{bar_x - 12}" y="{cy + 4}" text-anchor="end" fill="{label_fill}" '
            f'font-size="12" font-weight="{font_w}">{escape(label)}</text>'
        )
        parts.append(
            f'<rect x="{bar_x}" y="{row_y}" width="{bar_max_w:.1f}" height="20" rx="5" fill="{TRACK}"/>'
        )
        parts.append(
            f'<rect x="{bar_x}" y="{row_y}" width="{bw:.1f}" height="20" rx="5" fill="{color}"/>'
        )
        parts.append(
            f'<text x="{bar_x + bw + 8:.1f}" y="{cy + 4}" fill="{val_fill}" '
            f'font-size="12" font-weight="{font_w}">{escape(fmt_num(value, suffix))}</text>'
        )
        row_y += row_step

    return "\n  ".join(parts)


def build_overview_svg() -> str:
    w, h = 1120, 650
    pw, ph = 528, 252
    gap = 20
    left_x = 22
    right_x = left_x + pw + gap
    top_y = 78
    bot_y = top_y + ph + gap

    stdio_rps = [
        ("gocloak-mcp (Go)", 1227.2, ACCENT, True),
        ("MnemoShare (Go)", 1161.3, COMP_GO, False),
        ("Haitham (TS/Node)", 480.3, COMP_TS, False),
        ("idoyudha (Python)", 145.0, COMP_PY, False),
    ]
    http_rps = [
        ("gocloak-mcp (Go)", 1139.9, ACCENT, True),
        ("MnemoShare (Go)", 1120.1, COMP_GO, False),
        ("sshaaf Quarkus Native", 204.9, COMP_JAVA, False),
        ("sshaaf Quarkus JVM", 158.1, COMP_JVM, False),
    ]
    cold_start = [
        ("gocloak-mcp (Stdio)", 9.9, ACCENT, True),
        ("MnemoShare (Stdio)", 20.0, COMP_GO, False),
        ("sshaaf Quarkus Native", 63.5, COMP_JAVA, False),
        ("Haitham (TS/Node)", 114.1, COMP_TS, False),
        ("idoyudha (Python)", 591.4, COMP_PY, False),
        ("sshaaf Quarkus JVM", 2024.1, COMP_JVM, False),
    ]
    rss_load = [
        ("gocloak-mcp (Stdio)", 16.2, ACCENT, True),
        ("gocloak-mcp (HTTP)", 17.4, ACCENT_2, True),
        ("MnemoShare (HTTP)", 18.5, COMP_GO, False),
        ("idoyudha (Python)", 64.1, COMP_PY, False),
        ("Haitham (TS/Node)", 97.6, COMP_TS, False),
        ("sshaaf Native / JVM", 310.8, COMP_JVM, False),
    ]

    p1 = render_bar_panel(
        left_x, top_y, pw, ph,
        "Stdio Throughput (req/s)",
        "Higher is better · 50 users/call · 100 sequential calls",
        stdio_rps, " req/s", max_val=1300,
    )
    p2 = render_bar_panel(
        right_x, top_y, pw, ph,
        "Streamable HTTP Throughput (req/s)",
        "Higher is better · 50 users/call · 300 calls @ 10 workers",
        http_rps, " req/s", max_val=1300,
    )
    p3 = render_bar_panel(
        left_x, bot_y, pw, ph,
        "Cold Start Time (ms)",
        "Lower is better · median to first MCP initialize response",
        cold_start, " ms", max_val=2100,
    )
    p4 = render_bar_panel(
        right_x, bot_y, pw, ph,
        "Memory Footprint Under Load (MB RSS)",
        "Lower is better · sshaaf Native: 151.4 MB, JVM: 310.8 MB",
        rss_load, " MB", max_val=330,
    )

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="gocloak-mcp v0.3.0 Head-to-Head Benchmarks">
  <defs>
    <style>
      text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    </style>
  </defs>
  <rect width="{w}" height="{h}" rx="16" fill="{BG}" stroke="{BORDER}" stroke-width="1"/>
  <text x="24" y="36" fill="{TEXT}" font-size="20" font-weight="800">gocloak-mcp v0.3.0 — Head-to-Head Keycloak MCP Benchmarks</text>
  <text x="24" y="57" fill="{MUTED}" font-size="12.5">Measured on ubuntu-latest (4 vCPU x86_64) · Identical local mock Keycloak Admin API (50 users/call) · Go 1.27.4 + gocloak v15.1.0</text>
  <rect x="{w - 230}" y="20" width="206" height="30" rx="15" fill="#0d2b24" stroke="{ACCENT}" stroke-width="1"/>
  <text x="{w - 127}" y="39" text-anchor="middle" fill="{ACCENT}" font-size="12" font-weight="700">#1 Stdio &amp; Streamable HTTP</text>
  {p1}
  {p2}
  {p3}
  {p4}
  <text x="24" y="{h - 14}" fill="{MUTED}" font-size="11">OCI Container Image: gocloak-mcp 21.1 MB (distroless nonroot) vs. sshaaf/keycloak-mcp-server 626 MB (29.7x larger) · Reproducible via benchmarks/run_benchmarks.py</text>
</svg>
'''


def build_pprof_svg() -> str:
    w, h = 1120, 340
    pw, ph = 528, 226
    left_x = 22
    right_x = left_x + pw + 20
    top_y = 78

    latency = [
        ("Baseline (v0.2.0)", 1224.7, "#6e7681", False),
        ("v1: Direct Output + JSON", 735.7, COMP_GO, False),
        ("v2: Go 1.27 json/v2", 641.1, ACCENT_2, False),
        ("v3: gocloak v15.1 Direct", 628.7, ACCENT, True),
    ]
    allocs = [
        ("Baseline (v0.2.0)", 5480.0, "#6e7681", False),
        ("v1: Direct Output + JSON", 1124.0, COMP_GO, False),
        ("v2: Go 1.27 json/v2", 1064.0, ACCENT_2, False),
        ("v3: gocloak v15.1 Direct", 1059.0, ACCENT, True),
    ]

    p1 = render_bar_panel(
        left_x, top_y, pw, ph,
        "End-to-End HTTP Latency (µs/op)",
        "Lower is better · -48.7% latency reduction (1.95x faster)",
        latency, " µs", max_val=1300,
    )
    p2 = render_bar_panel(
        right_x, top_y, pw, ph,
        "Heap Allocations per Call (allocs/op)",
        "Lower is better · -80.7% fewer allocations (5.17x fewer)",
        allocs, " allocs", max_val=5800,
    )

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-label="gocloak-mcp pprof Optimization Progression">
  <defs>
    <style>
      text {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    </style>
  </defs>
  <rect width="{w}" height="{h}" rx="16" fill="{BG}" stroke="{BORDER}" stroke-width="1"/>
  <text x="24" y="36" fill="{TEXT}" font-size="20" font-weight="800">pprof-Driven Optimization Progression (v0.2.0 → v0.3.0)</text>
  <text x="24" y="57" fill="{MUTED}" font-size="12.5">BenchmarkEndToEndHTTPListUsers50 (50 users/call, Intel Xeon Platinum 8481C, Go 1.27.4) · Saved profiles in benchmarks/profiles/</text>
  {p1}
  {p2}
  <text x="24" y="{h - 14}" fill="{MUTED}" font-size="11">Verify diff: go tool pprof -top -diff_base=benchmarks/profiles/baseline/e2e_http_mem.prof benchmarks/profiles/optimized_v3/e2e_http_mem.prof</text>
</svg>
'''


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "benchmark-overview.svg").write_text(build_overview_svg(), encoding="utf-8")
    (OUT_DIR / "pprof-progression.svg").write_text(build_pprof_svg(), encoding="utf-8")
    print(f"Generated SVGs in {OUT_DIR}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
