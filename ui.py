"""
ui.py -- live presentation for --tvla and --fuzz-lattice.

Uses `rich` when available and attached to a TTY; otherwise falls back to
periodic plain-text status lines so the tool is still usable in CI / piped
output. The live views are refreshed *manually* from the driving loop
(auto_refresh disabled) so no background render thread exists at os.fork()
time in the fuzzer.
"""

from __future__ import annotations

import sys
import time
from typing import Optional

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich import box
    _HAVE_RICH = True
except Exception:  # pragma: no cover
    _HAVE_RICH = False


def _interactive() -> bool:
    return _HAVE_RICH and sys.stdout.isatty()


def _bar(value: float, vmax: float, width: int, char: str = "█") -> str:
    if vmax <= 0:
        return ""
    filled = int(min(1.0, value / vmax) * width)
    return char * filled + "░" * (width - filled)


# ===========================================================================
# TVLA
# ===========================================================================

def _tvla_render(target, cfg, snap):
    thr = cfg.threshold
    color = "bright_red" if snap.leaking else ("yellow" if snap.max_abs_t > thr * 0.6 else "bright_green")

    head = Table.grid(padding=(0, 2))
    head.add_column(justify="left")
    head.add_column(justify="left")
    head.add_row(f"[bold]target[/bold] {target.params.name}",
                 f"[bold]probe symbol[/bold] {target.probe_name}")
    head.add_row(f"[bold]mode[/bold] {cfg.mode}",
                 f"[bold]threshold[/bold] |t| > {thr}")
    core_desc = snap.pinned_core if snap.pinned_core is not None else "unpinned"
    head.add_row(f"[bold]pinned core[/bold] {core_desc}", "")

    stats = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False)
    stats.add_column("metric", style="dim")
    stats.add_column("value", justify="right")
    stats.add_row("iterations", f"{snap.iterations:,}")
    stats.add_row("exec/s", f"{snap.exec_per_s:,.0f}")
    stats.add_row("t (current)", f"[{color}]{snap.t:+.3f}[/{color}]")
    stats.add_row("max |t|", f"[{color}]{snap.max_abs_t:.3f}[/{color}]")
    stats.add_row("p-value", f"{snap.p_value:.2e}")
    stats.add_row("mean A / B (cyc)", f"{snap.mean_a:,.1f} / {snap.mean_b:,.1f}")
    stats.add_row("Δ mean (cyc)", f"{snap.diff:+.2f}")
    stats.add_row("95% CI of Δ", f"[{snap.ci95[0]:+.2f}, {snap.ci95[1]:+.2f}]")
    stats.add_row("n_A / n_B", f"{snap.n_a:,} / {snap.n_b:,}")

    # |t| relative to threshold, with a visible marker at the threshold.
    scale = max(thr * 1.5, snap.max_abs_t)
    tbar = _bar(snap.max_abs_t, scale, 40)
    marker_pos = int(min(1.0, thr / scale) * 40)
    tbar = tbar[:marker_pos] + "|" + tbar[marker_pos + 1:]
    graph = Table.grid()
    graph.add_column()
    graph.add_row(Text(f"|t|  {tbar}  {snap.max_abs_t:5.2f}", style=color))
    # Divergence view: two mean bars sharing a scale.
    lo = min(snap.mean_a, snap.mean_b)
    span = max(1.0, abs(snap.mean_a - snap.mean_b) * 4)
    graph.add_row(Text(f" A   {_bar(snap.mean_a - lo, span, 40, '▓')}", style="cyan"))
    graph.add_row(Text(f" B   {_bar(snap.mean_b - lo, span, 40, '▓')}", style="magenta"))

    if snap.leaking:
        verdict = Panel(Align.center(Text(
            f" LEAK DETECTED  |t| = {snap.max_abs_t:.2f} > {thr}  "
            f"(Δ = {snap.diff:+.2f} cyc, p = {snap.p_value:.1e}) ",
            style="bold white on red")), box=box.HEAVY, style="red")
    else:
        verdict = Panel(Align.center(Text(
            f" no leak at |t| > {thr} yet — keep sampling ",
            style="bold black on green")), box=box.ROUNDED, style="green")

    body = Group(head, Text(""), stats, Text(""), graph, Text(""), verdict)
    return Panel(body, title="[bold]LatticeScope · TVLA timing leakage[/bold]",
                 border_style=color, box=box.DOUBLE)


def run_tvla_ui(test, cfg, target):
    if not _interactive():
        return _run_tvla_plain(test, cfg, target)
    console = Console()
    final = None
    with Live(console=console, auto_refresh=False, screen=False) as live:
        last = 0.0
        for snap in test.run():
            final = snap
            now = time.perf_counter()
            if now - last >= 0.08 or snap.leaking:
                live.update(_tvla_render(target, cfg, snap), refresh=True)
                last = now
            if snap.leaking and cfg.stop_on_leak:
                break
        if final:
            live.update(_tvla_render(target, cfg, final), refresh=True)
    return final


def _run_tvla_plain(test, cfg, target):
    print(f"[TVLA] target={target.params.name} probe={target.probe_name} "
          f"mode={cfg.mode} threshold=|t|>{cfg.threshold}")
    final = None
    last = 0.0
    core_reported = False
    for snap in test.run():
        final = snap
        if not core_reported:
            core_desc = snap.pinned_core if snap.pinned_core is not None else "unpinned"
            print(f"  pinned core: {core_desc}")
            core_reported = True
        now = time.perf_counter()
        if now - last >= 0.5 or snap.leaking:
            print(f"  iter={snap.iterations:>10,}  exec/s={snap.exec_per_s:>9,.0f}  "
                  f"t={snap.t:+.3f}  max|t|={snap.max_abs_t:.3f}  "
                  f"Δ={snap.diff:+.2f}cyc  p={snap.p_value:.1e}")
            last = now
        if snap.leaking:
            print(f"  *** LEAK: max|t|={snap.max_abs_t:.2f} > {cfg.threshold} "
                  f"Δ={snap.diff:+.2f}cyc CI95=[{snap.ci95[0]:+.2f},{snap.ci95[1]:+.2f}]")
            if cfg.stop_on_leak:
                break
    return final


# ===========================================================================
# Fuzzer
# ===========================================================================

def _fuzz_render(target, cfg, snap):
    head = Table.grid(padding=(0, 2))
    head.add_column(); head.add_column()
    surf = "crypto_kem_dec (ciphertext)" if cfg.surface == "ct" else "leaf poly_frombytes-style"
    head.add_row(f"[bold]target[/bold] {target.params.name}",
                 f"[bold]surface[/bold] {surf}")

    stats = Table(box=box.SIMPLE_HEAVY, expand=True, show_edge=False)
    stats.add_column("metric", style="dim"); stats.add_column("value", justify="right")
    stats.add_row("executions", f"{snap.iterations:,}")
    stats.add_row("exec/s", f"[bold cyan]{snap.exec_per_s:,.0f}[/bold cyan]")
    stats.add_row("forks", f"{snap.forks:,}")
    stats.add_row("active strategy", f"[yellow]{snap.current_strategy}[/yellow]")
    stats.add_row("crashes (total)", f"{snap.crashes}")
    stats.add_row("crashes (unique)", f"[bold red]{snap.unique_crashes}[/bold red]"
                  if snap.unique_crashes else "0")

    parts = [head, Text(""), stats]
    if snap.last_crash:
        c = snap.last_crash
        hexcut = c.payload_hex[:96] + ("…" if len(c.payload_hex) > 96 else "")
        touched = (", ".join(map(str, c.touched[:16])) +
                   ("…" if len(c.touched) > 16 else "")) if c.touched else "(byte-stream)"
        alert = Table.grid(padding=(0, 1))
        alert.add_column(style="bold white"); alert.add_column(style="white")
        alert.add_row("signal", f"[bold]{c.signal_name}[/bold]")
        alert.add_row("strategy", c.strategy)
        alert.add_row("detail", c.detail)
        alert.add_row("seed", str(c.seed))
        alert.add_row("touched coeffs", touched)
        alert.add_row("payload", f"{len(c.payload_hex)//2} B  {hexcut}")
        alert.add_row("saved", c.path)
        parts += [Text(""), Panel(alert, title="[blink] MEMORY VIOLATION [/blink]",
                                  border_style="red", box=box.HEAVY,
                                  style="bold white on red")]

    color = "red" if snap.unique_crashes else "green"
    return Panel(Group(*parts),
                 title="[bold]LatticeScope · structure-aware lattice fuzzer[/bold]",
                 border_style=color, box=box.DOUBLE)


def run_fuzz_ui(fuzzer, cfg, target):
    if not _interactive():
        return _run_fuzz_plain(fuzzer, cfg, target)
    console = Console()
    final = None
    with Live(console=console, auto_refresh=False, screen=False) as live:
        last = 0.0
        seen = 0
        for snap in fuzzer.run():
            final = snap
            now = time.perf_counter()
            crashed = snap.unique_crashes > seen
            seen = snap.unique_crashes
            if now - last >= 0.1 or crashed:
                live.update(_fuzz_render(target, cfg, snap), refresh=True)
                last = now
        if final:
            live.update(_fuzz_render(target, cfg, final), refresh=True)
    return final


def _run_fuzz_plain(fuzzer, cfg, target):
    print(f"[FUZZ] target={target.params.name} surface={cfg.surface} "
          f"out={cfg.out_dir}")
    final = None
    last = 0.0
    seen = 0
    for snap in fuzzer.run():
        final = snap
        now = time.perf_counter()
        crashed = snap.unique_crashes > seen
        if crashed and snap.last_crash:
            c = snap.last_crash
            print(f"  !!! {c.signal_name} via {c.strategy} [{c.detail}] "
                  f"seed={c.seed} -> {c.path}")
            seen = snap.unique_crashes
        if now - last >= 0.5:
            print(f"  exec={snap.iterations:>10,}  exec/s={snap.exec_per_s:>9,.0f}  "
                  f"forks={snap.forks:>6,}  uniq_crashes={snap.unique_crashes}  "
                  f"[{snap.current_strategy}]")
            last = now
    return final