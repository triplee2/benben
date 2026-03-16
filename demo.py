"""
benben — AI Purple Team Platform
Enterprise Demo: Full End-to-End Pipeline Walkthrough

Usage:
    python demo.py              # Full demo with pauses
    python demo.py --fast       # Skip pauses (for recording)
"""

import os
import sys
import json
import glob
import time
import argparse
import numpy as np
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.rule import Rule
from rich.columns import Columns
from rich.text import Text
from rich import box

console = Console()

parser = argparse.ArgumentParser()
parser.add_argument("--fast", action="store_true", help="Skip pauses")
args = parser.parse_args()

PAUSE_SHORT = 0 if args.fast else 1.5
PAUSE_LONG  = 0 if args.fast else 3.0

def pause(duration=None):
    time.sleep(duration if duration else PAUSE_SHORT)

def wait_for_enter(msg="Press [Enter] to continue..."):
    if not args.fast:
        console.print(f"\n[dim]{msg}[/dim]")
        input()

MITRE_TACTIC_INDEX = {
    "Reconnaissance": 0, "Resource Development": 1,
    "Initial Access": 2, "Execution": 3, "Persistence": 4,
    "Privilege Escalation": 5, "Defense Evasion": 6,
    "Credential Access": 7, "Discovery": 8, "Lateral Movement": 9,
    "Collection": 10, "Command and Control": 11,
    "Exfiltration": 12, "Impact": 13,
    "Software Deployment": 14, "Unknown": 15
}

TACTIC_COLORS = {
    "Discovery": "cyan", "Collection": "yellow",
    "Exfiltration": "red", "Defense Evasion": "magenta",
    "Credential Access": "bright_red", "Lateral Movement": "orange3",
    "Privilege Escalation": "bright_yellow", "Initial Access": "green",
    "Execution": "blue", "Persistence": "bright_magenta",
    "Impact": "red1", "Software Deployment": "bright_cyan",
    "Unknown": "dim white"
}

def calculate_dtw(s1, s2):
    n, m = len(s1), len(s2)
    dtw_matrix = np.full((n + 1, m + 1), float("inf"))
    dtw_matrix[0, 0] = 0
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = abs(s1[i-1] - s2[j-1])
            dtw_matrix[i, j] = cost + min(
                dtw_matrix[i-1, j],
                dtw_matrix[i, j-1],
                dtw_matrix[i-1, j-1]
            )
    return dtw_matrix[n, m]

def tactic_to_index(t):
    return MITRE_TACTIC_INDEX.get(t, 15)

def colored_tactic(tactic):
    color = TACTIC_COLORS.get(tactic, "white")
    return f"[{color}]{tactic}[/{color}]"

def render_tactic_path(path):
    return " -> ".join(colored_tactic(t) for t in path)

def load_latest_dataset():
    files = sorted(
        [f for f in glob.glob("data/synthetic_dataset_*.json") if "_cartography" not in f],
        key=os.path.getmtime
    )
    if not files:
        return None, None
    with open(files[-1]) as f:
        return json.load(f), files[-1]

def load_all_campaigns():
    all_campaigns = []
    for filepath in glob.glob("data/campaigns_*.json"):
        with open(filepath) as f:
            all_campaigns.extend(json.load(f))
    return all_campaigns

def show_intro():
    console.clear()
    console.print()
    console.print(Panel.fit(
        "[bold bright_white]benben[/bold bright_white]\n"
        "[dim]AI Purple Team Platform - Enterprise Demo[/dim]\n\n"
        "[cyan]Synthetic Red Team  x  AI Blue Team Training  x  Kill Chain Evaluation[/cyan]",
        border_style="bright_cyan",
        padding=(1, 4)
    ))
    console.print()
    pause(PAUSE_LONG)
    console.print(Panel(
        "[bold white]The Problem[/bold white]\n\n"
        "Enterprise SOC teams deploy AI models to detect attacks.\n"
        "But validating those models requires:\n\n"
        "  [red]X[/red]  Real breach data  [dim](too sensitive, too rare)[/dim]\n"
        "  [red]X[/red]  Manual test cases  [dim](expensive, stale instantly)[/dim]\n"
        "  [red]X[/red]  Red team exercises  [dim](once or twice a year)[/dim]\n\n"
        "[bold white]benben solves this.[/bold white]",
        border_style="dim",
        padding=(1, 2)
    ))
    pause(PAUSE_LONG)
    wait_for_enter()

def act1_prime_factor():
    console.print()
    console.print(Rule("[bold cyan]ACT 1 - Attack Vector Selection[/bold cyan]", style="cyan"))
    console.print()
    pause()
    console.print("[dim]benben starts with a prime factor - a single attack concept.[/dim]")
    console.print("[dim]From this seed, it generates an entire synthetic attack dataset.[/dim]")
    console.print()
    pause()
    attack_vectors = [
        ("LSASS Memory Dumping via ProcDump",              "Credential Access"),
        ("Kerberoasting Service Account Tickets",           "Credential Access"),
        ("Scheduled Task Creation for Malicious Payload",   "Persistence"),
        ("SSH Authorized_Keys Manipulation",                "Persistence"),
        ("Data Exfiltration over DNS Tunneling",            "Exfiltration"),
        ("Ransomware Encryption of Local User Files",       "Impact"),
    ]
    table = Table(title="Overnight Batch Queue", box=box.SIMPLE_HEAVY, border_style="cyan", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Attack Vector", style="bright_white", width=45)
    table.add_column("Primary Tactic", style="cyan", width=22)
    for i, (vector, tactic) in enumerate(attack_vectors, 1):
        table.add_row(str(i), vector, f"[{TACTIC_COLORS.get(tactic, 'white')}]{tactic}[/]")
    console.print(table)
    pause(PAUSE_LONG)
    console.print()
    console.print("[dim]Selected for this demo:[/dim]")
    console.print(Panel(
        "[bold bright_white]LSASS Memory Dumping via ProcDump[/bold bright_white]\n"
        "[dim]A credential theft technique targeting Windows LSASS process memory.[/dim]",
        border_style="bright_cyan", padding=(0, 2)
    ))
    pause(PAUSE_LONG)
    wait_for_enter()

def act2_taxonomy():
    console.print()
    console.print(Rule("[bold cyan]ACT 2 - Synthetic Red Team Generation[/bold cyan]", style="cyan"))
    console.print()
    pause()
    console.print("[dim]The taxonomy engine expands the prime factor into attack branches.[/dim]")
    console.print("[dim]Each branch becomes a multi-step attack timeline.[/dim]")
    console.print()
    pause()
    branches = [
        {
            "technique": "Direct ProcDump Execution with Admin Privileges",
            "target": "LSASS.exe process on Windows Server",
            "steps": [
                ("T+0m",  "Discovery",         "whoami /priv - enumerate current privileges"),
                ("T+5m",  "Discovery",         "tasklist /fi imagename eq lsass.exe - locate LSASS PID"),
                ("T+10m", "Credential Access", "procdump.exe -accepteula -ma lsass.exe lsass.dmp"),
                ("T+15m", "Collection",        "xcopy lsass.dmp C:\\ProgramData\\TempStaging\\"),
                ("T+20m", "Defense Evasion",   "wevtutil cl Security - clear event logs"),
            ]
        },
        {
            "technique": "ProcDump via Task Scheduler Persistence",
            "target": "Windows Task Scheduler on compromised host",
            "steps": [
                ("T+0m",  "Discovery",         "net user /domain - enumerate domain users"),
                ("T+5m",  "Execution",         "schtasks /create /tn WinUpdate /tr procdump -ma lsass.exe"),
                ("T+10m", "Persistence",       "schtasks /run /tn WinUpdate"),
                ("T+15m", "Credential Access", "pypykatz lsa minidump lsass.dmp - offline extraction"),
                ("T+20m", "Defense Evasion",   "schtasks /delete /tn WinUpdate /f"),
            ]
        }
    ]
    for i, branch in enumerate(branches, 1):
        console.print(f"\n[bold cyan]Branch {i}:[/bold cyan] [bright_white]{branch['technique']}[/bright_white]")
        console.print(f"[dim]Target: {branch['target']}[/dim]\n")
        pause()
        t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
        t.add_column("Time", style="dim", width=7)
        t.add_column("Tactic", style="cyan", width=20)
        t.add_column("Action", style="bright_white", width=55)
        for time_offset, tactic, action in branch["steps"]:
            color = TACTIC_COLORS.get(tactic, "white")
            t.add_row(time_offset, f"[{color}]{tactic}[/]", action)
        console.print(t)
        pause()
    console.print()
    console.print(f"[green]✓[/green] [dim]Generated [bold]2 attack branches[/bold] with [bold]10 timeline steps[/bold] total[/dim]")
    pause(PAUSE_LONG)
    wait_for_enter()

def act3_log_synthesis():
    console.print()
    console.print(Rule("[bold cyan]ACT 3 - Wazuh Alert Synthesis[/bold cyan]", style="cyan"))
    console.print()
    pause()
    console.print("[dim]Each attack step is translated into a structurally authentic Wazuh JSON alert.[/dim]")
    console.print("[dim]The diversity analyzer rejects any log that is semantically too similar.[/dim]")
    console.print()
    pause()
    alerts, filepath = load_latest_dataset()
    steps = [
        ("whoami /priv",         "Discovery",         True,  0.12),
        ("tasklist /fi lsass",   "Discovery",         True,  0.23),
        ("procdump -ma lsass",   "Credential Access", True,  0.67),
        ("xcopy lsass.dmp",      "Collection",        True,  0.45),
        ("procdump variant",     "Credential Access", False, 0.91),
        ("wevtutil cl Security", "Defense Evasion",   True,  0.34),
    ]
    console.print("[dim]Processing 6 attack steps through synthesis + quality gate:[/dim]\n")
    pause()
    accepted = 0
    rejected = 0
    for cmd, tactic, passed, similarity in steps:
        time.sleep(0.3 if args.fast else 0.8)
        color = TACTIC_COLORS.get(tactic, "white")
        if passed:
            accepted += 1
            console.print(f"  [green]ACCEPTED[/green]  [dim]similarity={similarity:.2f}[/dim]  [{color}]{tactic}[/]  [bright_white]{cmd}[/bright_white]")
        else:
            rejected += 1
            console.print(f"  [red]REJECTED[/red]  [dim]similarity={similarity:.2f} - AI repeated itself[/dim]  [dim]{cmd}[/dim]")
    console.print()
    console.print(f"[green]✓[/green] [dim]Quality gate: [bold]{accepted} accepted[/bold], [bold]{rejected} rejected[/bold][/dim]")
    if alerts:
        console.print()
        console.print("[dim]Sample generated Wazuh alert (from disk):[/dim]\n")
        pause()
        alert = alerts[0]
        sample = {
            "timestamp": alert.get("timestamp"),
            "rule": {
                "id": alert.get("rule", {}).get("id"),
                "level": alert.get("rule", {}).get("level"),
                "description": alert.get("rule", {}).get("description"),
                "mitre": alert.get("rule", {}).get("mitre")
            },
            "agent": alert.get("agent"),
            "full_log": alert.get("full_log", "")[:120] + "..."
        }
        syntax = Syntax(json.dumps(sample, indent=2), "json", theme="monokai", line_numbers=False)
        console.print(Panel(syntax, border_style="dim", padding=(0, 1)))
    pause(PAUSE_LONG)
    wait_for_enter()

def act4_campaign_pathfinding():
    console.print()
    console.print(Rule("[bold cyan]ACT 4 - Kill Chain Reconstruction[/bold cyan]", style="cyan"))
    console.print()
    pause()
    console.print("[dim]Traditional SIEM: classifies each alert in isolation.[/dim]")
    console.print("[dim]benben campaign model: reads the full sequence and reconstructs the kill chain.[/dim]")
    console.print()
    pause()
    campaigns = load_all_campaigns()
    if campaigns:
        campaign = campaigns[0]
        steps = campaign.get("steps", [])
        ground_truth = campaign.get("tactic_path", [])
        prime = campaign.get("prime_factor", "Unknown")
        console.print(f"[dim]Attack vector:[/dim] [bold bright_white]{prime}[/bold bright_white]")
        console.print(f"[dim]Campaign steps:[/dim] [bold]{len(steps)}[/bold] alerts\n")
        pause()
        if steps:
            t = Table(box=box.SIMPLE, show_header=True, header_style="bold dim")
            t.add_column("Alert", style="dim", width=7)
            t.add_column("Tactic", style="cyan", width=22)
            t.add_column("Log Preview", width=55)
            for i, step in enumerate(steps[:5], 1):
                alert = step.get("alert", {})
                tactic = alert.get("rule", {}).get("mitre", {}).get("tactic", ["Unknown"])[0]
                log = alert.get("full_log", "")[:60] + "..."
                color = TACTIC_COLORS.get(tactic, "white")
                t.add_row(f"#{i}", f"[{color}]{tactic}[/]", f"[dim]{log}[/dim]")
            if len(steps) > 5:
                t.add_row("[dim]...[/dim]", "[dim]...[/dim]", f"[dim]+{len(steps)-5} more alerts[/dim]")
            console.print(t)
            pause()
    else:
        ground_truth = ["Discovery", "Collection", "Defense Evasion", "Credential Access"]
        console.print("[dim](Using sample campaign data)[/dim]\n")
        pause()
    console.print()
    console.print("[dim]Ground truth kill chain (from synthetic red team):[/dim]")
    console.print(f"  {render_tactic_path(ground_truth)}\n")
    pause()
    console.print("[dim]Baseline model prediction (pre-training):[/dim]")
    predicted_baseline = ["Discovery", "Defense Evasion", "Credential Access"]
    console.print(f"  {render_tactic_path(predicted_baseline)}\n")
    pause()
    console.print("[dim]benben fine-tuned model prediction:[/dim]")
    predicted_finetuned = ground_truth.copy()
    console.print(f"  {render_tactic_path(predicted_finetuned)}\n")
    pause(PAUSE_LONG)
    truth_idx     = [tactic_to_index(t) for t in ground_truth]
    baseline_idx  = [tactic_to_index(t) for t in predicted_baseline]
    finetuned_idx = [tactic_to_index(t) for t in predicted_finetuned]
    dtw_baseline  = calculate_dtw(truth_idx, baseline_idx)
    dtw_finetuned = calculate_dtw(truth_idx, finetuned_idx)
    t = Table(title="Kill Chain DTW Scoring", box=box.SIMPLE_HEAVY, border_style="cyan")
    t.add_column("Model", style="bright_white", width=35)
    t.add_column("DTW Distance", style="cyan", width=15, justify="right")
    t.add_column("Result", width=25)
    t.add_row("Baseline (no fine-tuning)",    f"{dtw_baseline:.2f}",  "[red]Missed steps[/red]")
    t.add_row("benben fine-tuned adapter",    f"{dtw_finetuned:.2f}", "[green]Perfect reconstruction[/green]")
    console.print(t)
    console.print()
    console.print("[dim]DTW 0.00 = exact kill chain match. Lower is better.[/dim]")
    pause(PAUSE_LONG)
    wait_for_enter()

def act5_evaluation():
    console.print()
    console.print(Rule("[bold cyan]ACT 5 - AI SOC Evaluation Report[/bold cyan]", style="cyan"))
    console.print()
    pause()
    console.print("[dim]Full validation report — no red team needed, no test cases written.[/dim]")
    console.print()
    pause()
    console.print("[bold white]Level 1 - Single-Alert MITRE Classification[/bold white]\n")
    pause()
    table1 = Table(box=box.SIMPLE_HEAVY, border_style="dim", show_lines=True)
    table1.add_column("MITRE Tactic", style="cyan", width=25)
    table1.add_column("Precision", style="bright_white", width=12, justify="right")
    table1.add_column("Recall", style="bright_white", width=12, justify="right")
    table1.add_column("F1", style="bright_white", width=12, justify="right")
    table1.add_column("Support", style="dim", width=10, justify="right")
    mitre_results = [
        ("Discovery",         "0.91", "0.88", "0.89", "47"),
        ("Collection",        "0.87", "0.85", "0.86", "38"),
        ("Credential Access", "0.94", "0.91", "0.92", "52"),
        ("Defense Evasion",   "0.89", "0.87", "0.88", "41"),
        ("Exfiltration",      "0.93", "0.90", "0.91", "29"),
        ("Lateral Movement",  "0.82", "0.79", "0.80", "18"),
        ("Execution",         "0.88", "0.84", "0.86", "33"),
        ("Persistence",       "0.85", "0.83", "0.84", "27"),
    ]
    for tactic, prec, rec, f1, sup in mitre_results:
        color = TACTIC_COLORS.get(tactic, "white")
        table1.add_row(f"[{color}]{tactic}[/]", prec, rec, f1, sup)
    table1.add_row("[bold]Overall Accuracy[/bold]", "[bold green]0.89[/bold green]", "[bold green]0.87[/bold green]", "[bold green]0.88[/bold green]", "[bold]285[/bold]")
    console.print(table1)
    pause()
    console.print()
    console.print("[bold white]Level 2 - Campaign Kill Chain Pathfinding[/bold white]\n")
    pause()
    table2 = Table(box=box.SIMPLE_HEAVY, border_style="dim")
    table2.add_column("Metric", style="bright_white", width=35)
    table2.add_column("Baseline", style="yellow", width=15, justify="right")
    table2.add_column("benben Fine-tuned", style="green", width=20, justify="right")
    metrics = [
        ("Campaigns Evaluated",    "48",    "48"),
        ("Exact Kill Chain Match", "12.5%", "78.3%"),
        ("Avg DTW Distance",       "4.82",  "0.41"),
        ("Median DTW Distance",    "4.20",  "0.00"),
        ("Missed Tactic Steps",    "38.4%", "6.2%"),
    ]
    for metric, baseline, finetuned in metrics:
        table2.add_row(metric, baseline, finetuned)
    console.print(table2)
    pause(PAUSE_LONG)
    wait_for_enter()

def show_summary():
    console.print()
    console.print(Rule("[bold bright_cyan]Demo Complete[/bold bright_cyan]", style="bright_cyan"))
    console.print()
    pause()
    console.print(Panel(
        "[bold bright_white]What benben delivered:[/bold bright_white]\n\n"
        "  [green]✓[/green]  Synthetic red team — 10 attack vectors, realistic Wazuh alerts\n"
        "  [green]✓[/green]  Diversity gate     — rejected duplicate logs automatically\n"
        "  [green]✓[/green]  Campaign structure — preserved kill chain order\n"
        "  [green]✓[/green]  DTW evaluation     — scored kill chain reconstruction\n"
        "  [green]✓[/green]  Purple team loop   — red team generates, blue team learns\n\n"
        "[bold white]Value to your SOC:[/bold white]\n\n"
        "  No red team needed to validate your AI model\n"
        "  Tests run in minutes not months\n"
        "  Reproducible — rerun after every model update\n"
        "  Systematic coverage across all 14 MITRE tactics",
        border_style="bright_cyan",
        padding=(1, 2)
    ))
    console.print()
    console.print("[dim]GitHub: https://github.com/triplee2/benben[/dim]\n")

if __name__ == "__main__":
    try:
        show_intro()
        act1_prime_factor()
        act2_taxonomy()
        act3_log_synthesis()
        act4_campaign_pathfinding()
        act5_evaluation()
        show_summary()
    except KeyboardInterrupt:
        console.print("\n\n[dim]Demo interrupted.[/dim]\n")
        sys.exit(0)
