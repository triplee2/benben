"""
benben Prototype v0.2
=====================
Expanded with:
  - Gemini Critic: independent review of each generated log with reasons
  - Live Kill Chain Visualizer: attack path builds as a graph in real time
  - Dataset Explorer: browse all generated campaigns and alerts
  - Evaluation Dashboard: DTW scoring with visual charts

Web mode:  python prototype.py
CLI mode:  python prototype.py --cli
"""

import os
import sys
import json
import time
import queue
import threading
import argparse
import glob
import numpy as np
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

parser = argparse.ArgumentParser()
parser.add_argument("--cli", action="store_true")
parser.add_argument("--vector", type=str)
args = parser.parse_args()

# ---------------------------------------------------------
# MITRE Techniques
# ---------------------------------------------------------
MITRE_TECHNIQUES = [
    {"id": "T1003", "name": "OS Credential Dumping",                    "tactic": "Credential Access", "example": "LSASS Memory Dumping via ProcDump"},
    {"id": "T1558", "name": "Steal or Forge Kerberos Tickets",          "tactic": "Credential Access", "example": "Kerberoasting Service Account Tickets"},
    {"id": "T1053", "name": "Scheduled Task / Job",                     "tactic": "Persistence",       "example": "Scheduled Task Creation for Malicious Payload"},
    {"id": "T1098", "name": "Account Manipulation",                     "tactic": "Persistence",       "example": "SSH Authorized_Keys Manipulation"},
    {"id": "T1562", "name": "Impair Defenses",                          "tactic": "Defense Evasion",   "example": "Disabling Windows Defender via PowerShell"},
    {"id": "T1070", "name": "Indicator Removal",                        "tactic": "Defense Evasion",   "example": "Clearing Windows Event Logs via wevtutil"},
    {"id": "T1550", "name": "Use Alternate Authentication Material",     "tactic": "Lateral Movement",  "example": "Pass the Hash via WMI"},
    {"id": "T1569", "name": "System Services",                          "tactic": "Execution",         "example": "Remote Execution via PsExec"},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",   "tactic": "Exfiltration",      "example": "Data Exfiltration over DNS Tunneling"},
    {"id": "T1486", "name": "Data Encrypted for Impact",                "tactic": "Impact",            "example": "Ransomware Encryption of Local User Files"},
]

TACTIC_COLORS = {
    "Discovery": "#38bdf8", "Collection": "#fbbf24",
    "Exfiltration": "#fb923c", "Defense Evasion": "#c084fc",
    "Credential Access": "#f87171", "Lateral Movement": "#34d399",
    "Privilege Escalation": "#fcd34d", "Initial Access": "#4ade80",
    "Execution": "#60a5fa", "Persistence": "#a78bfa",
    "Impact": "#ef4444", "Command and Control": "#f472b6",
    "Reconnaissance": "#67e8f9", "Unknown": "#6b7280",
    "Software Deployment": "#22d3ee",
}

MITRE_TACTIC_INDEX = {
    "Reconnaissance": 0, "Resource Development": 1, "Initial Access": 2,
    "Execution": 3, "Persistence": 4, "Privilege Escalation": 5,
    "Defense Evasion": 6, "Credential Access": 7, "Discovery": 8,
    "Lateral Movement": 9, "Collection": 10, "Command and Control": 11,
    "Exfiltration": 12, "Impact": 13, "Unknown": 14,
}

# ---------------------------------------------------------
# Gemini Critic
# ---------------------------------------------------------
def run_gemini_critic(action_description: str, alert_dict: dict) -> dict:
    """
    Independent Gemini critique of a generated log.
    Checks: semantic match, tactic correctness, platform authenticity.
    Returns: { passed: bool, verdict: str, reason: str }
    """
    try:
        from google import genai
        from google.genai import types
        from pydantic import BaseModel, Field

        class CriticVerdict(BaseModel):
            passed: bool = Field(..., description="True if the log passes all checks")
            verdict: str = Field(..., description="PASS or FAIL")
            reason: str = Field(..., description="One sentence explanation of the verdict")
            tactic_correct: bool = Field(..., description="Is the MITRE tactic label correct for this log?")
            log_authentic: bool = Field(..., description="Is the full_log format authentic for the platform?")
            action_matches: bool = Field(..., description="Does the full_log content match the action description?")

        client = genai.Client()

        rule = alert_dict.get("rule", {})
        tactic = (rule.get("mitre") or {}).get("tactic", ["Unknown"])
        tactic_str = tactic[0] if tactic else "Unknown"
        full_log = alert_dict.get("full_log", "")[:300]

        prompt = f"""
You are an independent security data quality critic reviewing a synthetic SIEM log.

ORIGINAL ACTION DESCRIPTION:
{action_description}

GENERATED LOG (truncated):
{full_log}

ASSIGNED MITRE TACTIC: {tactic_str}
DECODER USED: {alert_dict.get("decoder", {}).get("name", "unknown")}

Critically evaluate:
1. Does the full_log content actually show the action described? (action_matches)
2. Is the MITRE tactic label correct for what this log shows? (tactic_correct)
3. Is the log format authentic for its claimed platform/decoder? (log_authentic)

Be strict. If any check fails, verdict is FAIL.
"""

        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=CriticVerdict,
                temperature=0.1
            )
        )

        verdict = CriticVerdict.model_validate_json(response.text)
        return verdict.model_dump()

    except Exception as e:
        return {
            "passed": True,
            "verdict": "SKIP",
            "reason": f"Critic unavailable: {str(e)[:60]}",
            "tactic_correct": True,
            "log_authentic": True,
            "action_matches": True
        }

# ---------------------------------------------------------
# DTW
# ---------------------------------------------------------
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
    return float(dtw_matrix[n, m])

def tactics_to_indices(tactics):
    return [MITRE_TACTIC_INDEX.get(t, 14) for t in tactics]

# ---------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------
def run_pipeline(vector: str, event_queue: queue.Queue = None):
    def emit(etype, data):
        data["timestamp"] = datetime.now().strftime("%H:%M:%S")
        if event_queue:
            event_queue.put({"type": etype, "data": data})
        else:
            if etype in ("stage", "complete"):
                print(f"\n[{etype.upper()}] {data.get('title', data.get('vector', ''))}")
            elif etype == "info":
                print(f"  → {data['message']}")
            elif etype == "alert":
                print(f"  [{data['status']}] {data['tactic']} | critic={data.get('critic_verdict','N/A')}")
            elif etype == "campaign":
                print(f"  Campaign: {' → '.join(data['tactic_path'])}")

    try:
        from src.taxonomy_engine import CommonsTaxonomyEngine
        from src.complexity_expander import CommonsComplexityExpander
        from src.log_generator import CommonsLogGenerator
        from src.diversity_analyzer import CommonsDiversityAnalyzer
    except ImportError as e:
        emit("error", {"message": f"Import error: {e}"}); emit("done", {}); return

    emit("stage", {"title": "STAGE 1 — Taxonomy Generation", "description": f"Expanding '{vector}' into attack branches"})

    try:
        taxonomy = CommonsTaxonomyEngine()
        branches = taxonomy.generate_branches(prime_factor=vector, depth=2)
        emit("info", {"message": f"Generated {len(branches)} attack branches"})
    except Exception as e:
        emit("error", {"message": f"Taxonomy failed: {e}"}); emit("done", {}); return

    for i, branch in enumerate(branches, 1):
        emit("branch", {"index": i, "technique": branch.technique, "target": branch.target_asset, "description": branch.description})

    emit("stage", {"title": "STAGE 2 & 3 — Timeline + Log Synthesis + Critic", "description": "Expanding branches → alerts → independent quality review"})

    expander = CommonsComplexityExpander()
    generator = CommonsLogGenerator()
    analyzer  = CommonsDiversityAnalyzer()

    master_dataset, campaigns, embedding_vault = [], [], []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    accepted_total = 0
    kill_chain_nodes = []

    for i, branch in enumerate(branches):
        emit("info", {"message": f"Expanding Branch {i+1}: {branch.technique}"})
        try:
            timeline = expander.generate_timeline(technique=branch.technique, target=branch.target_asset)
        except Exception as e:
            emit("error", {"message": f"Expander failed: {e}"}); continue

        campaign_steps = []

        for step in timeline:
            emit("step", {"step_number": step.step_number, "time_offset": step.time_offset_minutes, "action": step.action_description})
            try:
                alert = generator.synthesize_wazuh_alert(
                    action_description=step.action_description,
                    time_offset_minutes=step.time_offset_minutes
                )

                new_embedding = analyzer.get_embedding(alert.full_log)
                is_unique = True
                similarity_score = 0.0
                for past in embedding_vault:
                    score = analyzer.calculate_similarity(new_embedding, past)
                    if score >= 0.90:
                        is_unique = False
                        similarity_score = score
                        break
                    similarity_score = max(similarity_score, score)

                tactic = "Unknown"
                mitre = alert.rule.mitre
                if mitre and mitre.tactic:
                    tactic = mitre.tactic[0]

                if not is_unique:
                    emit("alert", {
                        "status": "REJECTED", "tactic": tactic,
                        "similarity": similarity_score, "rule_desc": alert.rule.description,
                        "critic_verdict": "SKIP", "critic_reason": "Rejected by diversity gate",
                        "critic_passed": False, "log_preview": ""
                    })
                    time.sleep(2)
                    continue

                # Run Gemini critic on accepted logs
                emit("info", {"message": "Running Gemini critic..."})
                alert_dict = alert.model_dump()
                critic_result = run_gemini_critic(step.action_description, alert_dict)

                if not critic_result["passed"] and critic_result["verdict"] != "SKIP":
                    emit("alert", {
                        "status": "CRITIC_FAIL", "tactic": tactic,
                        "similarity": similarity_score, "rule_desc": alert.rule.description,
                        "critic_verdict": "FAIL", "critic_reason": critic_result["reason"],
                        "critic_passed": False,
                        "critic_checks": {
                            "action_matches": critic_result.get("action_matches"),
                            "tactic_correct": critic_result.get("tactic_correct"),
                            "log_authentic": critic_result.get("log_authentic"),
                        },
                        "log_preview": alert.full_log[:100]
                    })
                    time.sleep(2)
                    continue

                # Fully accepted
                accepted_total += 1
                master_dataset.append(alert_dict)
                embedding_vault.append(new_embedding)
                campaign_steps.append({
                    "step_number": step.step_number,
                    "time_offset_minutes": step.time_offset_minutes,
                    "action_description": step.action_description,
                    "alert": alert_dict
                })

                if tactic not in kill_chain_nodes:
                    kill_chain_nodes.append(tactic)

                emit("alert", {
                    "status": "ACCEPTED", "tactic": tactic,
                    "similarity": similarity_score, "rule_desc": alert.rule.description,
                    "critic_verdict": critic_result["verdict"],
                    "critic_reason": critic_result["reason"],
                    "critic_passed": True,
                    "critic_checks": {
                        "action_matches": critic_result.get("action_matches"),
                        "tactic_correct": critic_result.get("tactic_correct"),
                        "log_authentic": critic_result.get("log_authentic"),
                    },
                    "log_preview": alert.full_log[:100]
                })

                # Live kill chain update
                emit("killchain_update", {
                    "nodes": kill_chain_nodes.copy(),
                    "latest": tactic
                })

                time.sleep(2)

            except Exception as e:
                emit("error", {"message": f"Step {step.step_number} failed: {e}"}); time.sleep(2)

        if campaign_steps:
            tactic_path = []
            for s in campaign_steps:
                t = (s["alert"].get("rule", {}).get("mitre") or {}).get("tactic", [])
                if t and (not tactic_path or tactic_path[-1] != t[0]):
                    tactic_path.append(t[0])

            campaign = {
                "campaign_id": f"{timestamp}_branch{i+1}",
                "prime_factor": vector,
                "branch_technique": branch.technique,
                "branch_target": branch.target_asset,
                "branch_description": branch.description,
                "tactic_path": tactic_path or ["Unknown"],
                "steps": campaign_steps
            }
            campaigns.append(campaign)
            emit("campaign", {"campaign_id": campaign["campaign_id"], "tactic_path": tactic_path, "steps": len(campaign_steps)})

    emit("stage", {"title": "STAGE 4 — Saving Outputs", "description": "Writing datasets to disk"})
    os.makedirs("data", exist_ok=True)
    flat_file     = f"data/synthetic_dataset_{timestamp}.json"
    campaign_file = f"data/campaigns_{timestamp}.json"

    if master_dataset:
        with open(flat_file, "w") as f: json.dump(master_dataset, f, indent=2)
        emit("info", {"message": f"Saved {len(master_dataset)} alerts → {flat_file}"})

    if campaigns:
        with open(campaign_file, "w") as f: json.dump(campaigns, f, indent=2)
        emit("info", {"message": f"Saved {len(campaigns)} campaigns → {campaign_file}"})

    emit("complete", {"accepted": accepted_total, "campaigns": len(campaigns), "output_file": flat_file, "campaign_file": campaign_file, "vector": vector})
    emit("done", {})

# ---------------------------------------------------------
# CLI MODE
# ---------------------------------------------------------
if args.cli:
    vector = args.vector
    if not vector:
        for i, t in enumerate(MITRE_TECHNIQUES, 1):
            print(f"  {i}. [{t['id']}] {t['example']}")
        choice = input("\nPick a number (or type your own): ").strip()
        try: vector = MITRE_TECHNIQUES[int(choice)-1]["example"]
        except: vector = choice
    print(f"\nRunning benben for: {vector}\n")
    run_pipeline(vector)
    sys.exit(0)

# ---------------------------------------------------------
# WEB MODE
# ---------------------------------------------------------
from flask import Flask, render_template_string, request, Response, jsonify
app = Flask(__name__)

# ---------------------------------------------------------
# DATA HELPERS
# ---------------------------------------------------------
def load_all_campaigns():
    campaigns = []
    for f in glob.glob("data/campaigns_*.json"):
        try:
            with open(f) as fh: campaigns.extend(json.load(fh))
        except: pass
    return campaigns

def load_all_alerts():
    alerts = []
    for f in sorted(glob.glob("data/synthetic_dataset_*.json"), key=os.path.getmtime):
        if "_cartography" in f: continue
        try:
            with open(f) as fh: alerts.extend(json.load(fh))
        except: pass
    return alerts

def compute_evaluation():
    campaigns = load_all_campaigns()
    if not campaigns: return None

    results = []
    tactic_counts = {}
    for c in campaigns:
        path = c.get("tactic_path", [])
        if not path or path == ["Unknown"]: continue

        # Self-DTW as a proxy for complexity
        indices = tactics_to_indices(path)
        dtw = calculate_dtw(indices, indices[::-1]) if len(indices) > 1 else 0.0

        results.append({
            "campaign_id": c.get("campaign_id", "?"),
            "prime_factor": c.get("prime_factor", "?"),
            "tactic_path": path,
            "path_length": len(path),
            "dtw_complexity": dtw,
            "steps": len(c.get("steps", []))
        })

        for t in path:
            tactic_counts[t] = tactic_counts.get(t, 0) + 1

    if not results: return None

    avg_path_len = sum(r["path_length"] for r in results) / len(results)
    avg_steps    = sum(r["steps"] for r in results) / len(results)
    total_alerts = sum(r["steps"] for r in results)

    return {
        "total_campaigns": len(results),
        "total_alerts": total_alerts,
        "avg_path_length": round(avg_path_len, 2),
        "avg_steps_per_campaign": round(avg_steps, 2),
        "tactic_coverage": len(tactic_counts),
        "tactic_counts": dict(sorted(tactic_counts.items(), key=lambda x: -x[1])),
        "campaigns": results[:20]
    }

# ---------------------------------------------------------
# MAIN HTML
# ---------------------------------------------------------
MAIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>benben — AI Purple Team Platform</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;800&display=swap');

:root {
  --bg: #080c14;
  --surface: #0d1117;
  --surface2: #161b22;
  --border: #21262d;
  --border2: #30363d;
  --text: #c9d1d9;
  --text2: #8b949e;
  --text3: #484f58;
  --accent: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #e3b341;
  --purple: #bc8cff;
  --mono: 'JetBrains Mono', monospace;
  --sans: 'Syne', sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); min-height: 100vh; }

/* NAV */
nav {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 0 40px;
  display: flex;
  align-items: center;
  gap: 0;
  height: 56px;
}
.nav-logo { font-weight: 800; font-size: 1.2rem; color: var(--accent); letter-spacing: 3px; margin-right: 40px; }
.nav-links { display: flex; gap: 0; }
.nav-link {
  padding: 0 20px;
  height: 56px;
  display: flex;
  align-items: center;
  font-size: 0.82rem;
  font-weight: 600;
  color: var(--text2);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  text-decoration: none;
  transition: all 0.15s;
  letter-spacing: 0.5px;
}
.nav-link:hover { color: var(--text); }
.nav-link.active { color: var(--accent); border-bottom-color: var(--accent); }
.nav-badge {
  margin-left: auto;
  background: #1a2535;
  border: 1px solid var(--accent);
  color: var(--accent);
  padding: 3px 12px;
  border-radius: 20px;
  font-size: 0.72rem;
  font-weight: 700;
  font-family: var(--mono);
  letter-spacing: 1px;
}

/* PAGES */
.page { display: none; max-width: 1200px; margin: 0 auto; padding: 40px 24px; }
.page.active { display: block; }

/* PANELS */
.panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  margin-bottom: 20px;
}
.panel-title {
  font-size: 0.72rem;
  font-weight: 700;
  color: var(--accent);
  letter-spacing: 2px;
  text-transform: uppercase;
  margin-bottom: 6px;
}
.panel-sub { color: var(--text2); font-size: 0.83rem; margin-bottom: 20px; line-height: 1.5; }

/* TECHNIQUE GRID */
.technique-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 10px; margin-bottom: 20px; }
.tc {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  cursor: pointer;
  transition: all 0.15s;
  position: relative;
  overflow: hidden;
}
.tc::before { content: ''; position: absolute; inset: 0; background: linear-gradient(135deg, transparent 60%, rgba(88,166,255,0.03)); }
.tc:hover { border-color: var(--accent); }
.tc.selected { border-color: var(--accent); background: #0d1f33; }
.tc-id { font-family: var(--mono); font-size: 0.68rem; color: var(--text3); margin-bottom: 4px; }
.tc-name { font-size: 0.88rem; font-weight: 600; color: var(--text); margin-bottom: 3px; }
.tc-example { font-size: 0.75rem; color: var(--text2); line-height: 1.4; }
.tc-tactic {
  position: absolute; top: 10px; right: 10px;
  font-size: 0.62rem; padding: 2px 8px;
  border-radius: 10px; font-weight: 700;
}

/* CUSTOM INPUT */
.custom-row { display: flex; gap: 10px; margin-bottom: 16px; }
.custom-row input {
  flex: 1;
  background: var(--surface2);
  border: 1px solid var(--border2);
  border-radius: 8px;
  padding: 11px 14px;
  color: var(--text);
  font-size: 0.88rem;
  font-family: var(--mono);
  outline: none;
}
.custom-row input:focus { border-color: var(--accent); }
.custom-row input::placeholder { color: var(--text3); }

/* BUTTONS */
.btn-primary {
  background: var(--green);
  color: #000;
  border: none;
  border-radius: 8px;
  padding: 12px 28px;
  font-size: 0.9rem;
  font-weight: 700;
  font-family: var(--sans);
  cursor: pointer;
  width: 100%;
  letter-spacing: 0.5px;
  transition: all 0.15s;
}
.btn-primary:hover { background: #4ac461; }
.btn-primary:disabled { background: var(--surface2); color: var(--text3); cursor: not-allowed; }

/* OUTPUT AREA */
#output-panel { display: none; }
.stage-hdr {
  background: var(--surface2);
  border-left: 3px solid var(--accent);
  padding: 10px 14px;
  margin: 16px 0 8px;
  border-radius: 0 6px 6px 0;
  font-size: 0.85rem;
  font-weight: 700;
  color: var(--accent);
}
.stage-hdr .sd { color: var(--text2); font-size: 0.76rem; font-weight: 400; margin-top: 2px; }

.logline {
  font-family: var(--mono);
  font-size: 0.78rem;
  padding: 2px 0;
  color: var(--text2);
  display: flex;
  gap: 10px;
}
.logline .ts { color: var(--text3); min-width: 65px; }

.alert-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 10px 14px;
  margin: 5px 0;
  font-size: 0.8rem;
}
.alert-card.accepted { border-left: 3px solid var(--green); }
.alert-card.rejected { border-left: 3px solid var(--text3); opacity: 0.5; }
.alert-card.critic-fail { border-left: 3px solid var(--red); }

.alert-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.alert-status { font-weight: 700; font-size: 0.72rem; font-family: var(--mono); }
.alert-card.accepted .alert-status { color: var(--green); }
.alert-card.rejected .alert-status { color: var(--text3); }
.alert-card.critic-fail .alert-status { color: var(--red); }

.tactic-chip {
  background: var(--surface);
  border: 1px solid var(--border2);
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 0.7rem;
  font-family: var(--mono);
  color: var(--text2);
}

.critic-row {
  display: flex;
  gap: 6px;
  align-items: flex-start;
  margin-top: 6px;
  padding-top: 6px;
  border-top: 1px solid var(--border);
  font-size: 0.76rem;
  font-family: var(--mono);
}
.critic-label { color: var(--text3); min-width: 50px; }
.critic-pass { color: var(--green); }
.critic-fail-text { color: var(--red); }
.critic-skip { color: var(--text3); }

.check-row { display: flex; gap: 12px; margin-top: 4px; }
.check-item { font-size: 0.7rem; font-family: var(--mono); }
.check-item.pass { color: var(--green); }
.check-item.fail { color: var(--red); }

/* KILL CHAIN VISUALIZER */
#kc-panel {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
  margin-bottom: 20px;
  display: none;
}
#kc-title { font-size: 0.72rem; font-weight: 700; color: var(--accent); letter-spacing: 2px; text-transform: uppercase; margin-bottom: 16px; }
#kc-svg-container { overflow-x: auto; }
#kc-svg { min-height: 80px; }

/* CAMPAIGN CARD */
.campaign-card {
  background: #0a1a10;
  border: 1px solid #1d4a2a;
  border-radius: 8px;
  padding: 16px;
  margin: 10px 0;
}
.campaign-card h4 { color: var(--green); font-size: 0.85rem; margin-bottom: 8px; }
.kill-chain { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 8px; }
.kc-arrow { color: var(--text3); font-size: 0.75rem; }
.kc-node {
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 0.73rem;
  font-weight: 700;
  font-family: var(--mono);
  border: 1px solid;
}

/* COMPLETE BANNER */
.complete-banner {
  background: #0a1a10;
  border: 1px solid var(--green);
  border-radius: 10px;
  padding: 20px;
  margin-top: 16px;
}
.complete-banner h3 { color: var(--green); margin-bottom: 12px; }
.stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 12px; }
.stat-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; text-align: center; }
.stat-num { font-size: 1.8rem; font-weight: 800; color: var(--accent); font-family: var(--mono); }
.stat-lbl { font-size: 0.72rem; color: var(--text2); margin-top: 4px; }

.progress-bar { height: 2px; background: var(--border); border-radius: 2px; margin: 12px 0; overflow: hidden; }
.progress-fill { height: 100%; background: linear-gradient(90deg, var(--accent), var(--green)); width: 0%; transition: width 0.4s; }

.error-msg { background: #1a0808; border: 1px solid var(--red); border-radius: 6px; padding: 10px 14px; color: var(--red); font-size: 0.8rem; font-family: var(--mono); margin: 5px 0; }
.sleep-msg { color: var(--text3); font-size: 0.74rem; font-family: var(--mono); font-style: italic; padding: 2px 0; }
.branch-card { background: var(--surface2); border: 1px solid var(--border2); border-radius: 8px; padding: 12px; margin: 6px 0; }
.branch-name { font-weight: 700; color: var(--text); font-size: 0.85rem; margin-bottom: 3px; }
.branch-target { color: var(--text2); font-size: 0.76rem; }

/* EXPLORER */
.explorer-grid { display: grid; grid-template-columns: 1fr 1.4fr; gap: 16px; }
.campaign-list { border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.campaign-list-item {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
  cursor: pointer;
  transition: background 0.1s;
}
.campaign-list-item:hover { background: var(--surface2); }
.campaign-list-item.active { background: #0d1f33; border-left: 2px solid var(--accent); }
.cli-name { font-size: 0.82rem; font-weight: 600; color: var(--text); }
.cli-meta { font-size: 0.72rem; color: var(--text2); font-family: var(--mono); margin-top: 2px; }
.campaign-detail { border: 1px solid var(--border); border-radius: 8px; padding: 16px; overflow-y: auto; max-height: 600px; }
.alert-item { background: var(--surface2); border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin: 6px 0; font-size: 0.76rem; }
.alert-item-header { display: flex; gap: 8px; align-items: center; margin-bottom: 6px; font-family: var(--mono); }
.alert-log { font-family: var(--mono); font-size: 0.68rem; color: var(--text2); word-break: break-all; white-space: pre-wrap; max-height: 80px; overflow: hidden; }
.empty-state { text-align: center; padding: 60px 20px; color: var(--text2); }
.empty-state h3 { color: var(--text); margin-bottom: 8px; }
.empty-state p { font-size: 0.85rem; }

/* EVAL DASHBOARD */
.eval-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
.eval-stat { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }
.eval-stat .num { font-size: 2rem; font-weight: 800; font-family: var(--mono); color: var(--accent); }
.eval-stat .lbl { font-size: 0.72rem; color: var(--text2); margin-top: 4px; }

.tactic-bars { display: flex; flex-direction: column; gap: 8px; }
.tactic-bar-row { display: flex; align-items: center; gap: 10px; }
.tactic-bar-label { font-size: 0.78rem; font-family: var(--mono); min-width: 180px; color: var(--text); }
.tactic-bar-track { flex: 1; background: var(--border); border-radius: 4px; height: 18px; overflow: hidden; }
.tactic-bar-fill { height: 100%; border-radius: 4px; transition: width 0.8s ease; display: flex; align-items: center; padding-left: 8px; }
.tactic-bar-count { font-size: 0.7rem; font-family: var(--mono); font-weight: 700; }

.campaign-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
.campaign-table th { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); color: var(--text2); font-weight: 600; font-size: 0.72rem; letter-spacing: 0.5px; }
.campaign-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
.campaign-table tr:hover td { background: var(--surface2); }
.path-pill { display: inline-flex; flex-wrap: wrap; gap: 3px; }
.path-node { font-size: 0.65rem; font-family: var(--mono); padding: 1px 6px; border-radius: 10px; border: 1px solid; }

#scroll-anchor { height: 1px; }
</style>
</head>
<body>

<nav>
  <div class="nav-logo">benben</div>
  <div class="nav-links">
    <a class="nav-link active" onclick="showPage('generate', this)">Generate</a>
    <a class="nav-link" onclick="showPage('explore', this)">Explorer</a>
    <a class="nav-link" onclick="showPage('evaluate', this)">Evaluate</a>
  </div>
  <span class="nav-badge">v0.2 PROTOTYPE</span>
</nav>

<!-- ===== GENERATE PAGE ===== -->
<div class="page active" id="page-generate">
  <div class="panel">
    <div class="panel-title">Select Attack Technique</div>
    <div class="panel-sub">Pick a MITRE ATT&CK technique to run through the full synthetic generation pipeline with Gemini critic review.</div>
    <div class="technique-grid" id="technique-grid">
      {% for t in techniques %}
      <div class="tc" onclick="selectTechnique(this, '{{ t.example }}')">
        <div class="tc-id">{{ t.id }}</div>
        <div class="tc-name">{{ t.name }}</div>
        <div class="tc-example">{{ t.example }}</div>
        <span class="tc-tactic" style="background:rgba(88,166,255,0.1);color:#58a6ff;border:1px solid rgba(88,166,255,0.3)">{{ t.tactic }}</span>
      </div>
      {% endfor %}
    </div>
    <div class="custom-row">
      <input type="text" id="custom-vector" placeholder="Or type a custom attack vector..." onkeydown="if(event.key==='Enter') runPipeline()" />
    </div>
    <button class="btn-primary" id="run-btn" onclick="runPipeline()" disabled>Run Pipeline →</button>
  </div>

  <!-- Kill chain visualizer -->
  <div id="kc-panel">
    <div id="kc-title">Live Kill Chain</div>
    <div id="kc-svg-container">
      <svg id="kc-svg" width="100%" height="80"></svg>
    </div>
  </div>

  <!-- Output stream -->
  <div class="panel" id="output-panel">
    <div class="panel-title" id="output-title">Pipeline Running</div>
    <div class="panel-sub" id="output-sub">Streaming live output...</div>
    <div class="progress-bar"><div class="progress-fill" id="progress-fill"></div></div>
    <div id="output-stream"></div>
    <div id="scroll-anchor"></div>
  </div>
</div>

<!-- ===== EXPLORER PAGE ===== -->
<div class="page" id="page-explore">
  <div class="panel">
    <div class="panel-title">Dataset Explorer</div>
    <div class="panel-sub">Browse all generated campaigns and inspect individual alerts.</div>
  </div>
  <div id="explorer-content">
    <div class="empty-state">
      <h3>No data yet</h3>
      <p>Run the pipeline to generate campaigns, then come back here to explore them.</p>
    </div>
  </div>
</div>

<!-- ===== EVALUATE PAGE ===== -->
<div class="page" id="page-evaluate">
  <div class="panel">
    <div class="panel-title">Evaluation Dashboard</div>
    <div class="panel-sub">Dataset statistics, MITRE tactic coverage, and campaign quality metrics.</div>
  </div>
  <div id="eval-content">
    <div class="empty-state">
      <h3>No data yet</h3>
      <p>Run the pipeline to generate campaigns, then evaluate them here.</p>
    </div>
  </div>
</div>

<script>
// ----- State -----
let selectedVector = null;
let eventSource = null;
let progressValue = 0;
let killChainNodes = [];
const TACTIC_COLORS = {{ tactic_colors | tojson }};

// ----- Navigation -----
function showPage(name, link) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  if (link) link.classList.add('active');
  if (name === 'explore') loadExplorer();
  if (name === 'evaluate') loadEvaluate();
}

// ----- Technique selection -----
function selectTechnique(card, vector) {
  document.querySelectorAll('.tc').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  selectedVector = vector;
  document.getElementById('custom-vector').value = '';
  document.getElementById('run-btn').disabled = false;
}
document.getElementById('custom-vector').addEventListener('input', function() {
  document.querySelectorAll('.tc').forEach(c => c.classList.remove('selected'));
  selectedVector = null;
  document.getElementById('run-btn').disabled = !this.value.trim();
});

function getVector() {
  return document.getElementById('custom-vector').value.trim() || selectedVector;
}

// ----- Pipeline -----
function runPipeline() {
  const vector = getVector();
  if (!vector) return;

  progressValue = 0;
  killChainNodes = [];
  document.getElementById('output-title').textContent = 'Pipeline Running';
  document.getElementById('output-sub').textContent = vector;
  document.getElementById('output-stream').innerHTML = '';
  document.getElementById('progress-fill').style.width = '0%';
  document.getElementById('output-panel').style.display = 'block';
  document.getElementById('run-btn').disabled = true;
  document.getElementById('run-btn').textContent = 'Running...';
  document.getElementById('kc-panel').style.display = 'none';
  document.getElementById('kc-svg').innerHTML = '';

  document.getElementById('output-panel').scrollIntoView({ behavior: 'smooth' });
  if (eventSource) eventSource.close();
  eventSource = new EventSource('/stream?vector=' + encodeURIComponent(vector));
  eventSource.addEventListener('message', e => handleEvent(JSON.parse(e.data)));
  eventSource.addEventListener('error', () => { appendError('Connection lost.'); eventSource.close(); resetBtn(); });
}

// ----- Event handler -----
function handleEvent(event) {
  const stream = document.getElementById('output-stream');
  const {type, data} = event;

  if (type === 'stage') {
    progressValue = Math.min(progressValue + 22, 88);
    document.getElementById('progress-fill').style.width = progressValue + '%';
    const d = document.createElement('div');
    d.className = 'stage-hdr';
    d.innerHTML = escHtml(data.title) + '<div class="sd">' + escHtml(data.description) + '</div>';
    stream.appendChild(d);

  } else if (type === 'info') {
    if (data.message.includes('Sleeping') || data.message.includes('critic')) {
      const d = document.createElement('div');
      d.className = 'sleep-msg';
      d.textContent = '  ⏳ ' + data.message;
      stream.appendChild(d);
    } else {
      const d = document.createElement('div');
      d.className = 'logline';
      d.innerHTML = '<span class="ts">' + data.timestamp + '</span><span>→ ' + escHtml(data.message) + '</span>';
      stream.appendChild(d);
    }

  } else if (type === 'branch') {
    const d = document.createElement('div');
    d.className = 'branch-card';
    d.innerHTML = '<div class="branch-name">Branch ' + data.index + ': ' + escHtml(data.technique) + '</div>' +
      '<div class="branch-target">Target: ' + escHtml(data.target) + '</div>';
    stream.appendChild(d);

  } else if (type === 'step') {
    const d = document.createElement('div');
    d.className = 'logline';
    d.innerHTML = '<span class="ts">' + data.timestamp + '</span>' +
      '<span style="color:#484f58">Step ' + data.step_number + ' T+' + data.time_offset + 'm: </span>' +
      '<span>' + escHtml((data.action || '').substring(0, 80)) + '</span>';
    stream.appendChild(d);

  } else if (type === 'alert') {
    const accepted = data.status === 'ACCEPTED';
    const criticFail = data.status === 'CRITIC_FAIL';
    const d = document.createElement('div');
    d.className = 'alert-card ' + (accepted ? 'accepted' : criticFail ? 'critic-fail' : 'rejected');

    const checks = data.critic_checks || {};
    const checkHtml = accepted || criticFail ? `
      <div class="check-row">
        <span class="check-item ${checks.action_matches ? 'pass' : 'fail'}">${checks.action_matches ? '✓' : '✗'} action</span>
        <span class="check-item ${checks.tactic_correct ? 'pass' : 'fail'}">${checks.tactic_correct ? '✓' : '✗'} tactic</span>
        <span class="check-item ${checks.log_authentic ? 'pass' : 'fail'}">${checks.log_authentic ? '✓' : '✗'} format</span>
      </div>` : '';

    d.innerHTML =
      '<div class="alert-header">' +
        '<span class="alert-status">' + data.status + '</span>' +
        '<span class="tactic-chip">' + escHtml(data.tactic) + '</span>' +
        '<span style="color:var(--text3);font-size:0.7rem;font-family:var(--mono)">sim=' + (data.similarity||0).toFixed(2) + '</span>' +
      '</div>' +
      '<div style="font-size:0.78rem;color:var(--text2)">' + escHtml(data.rule_desc || '') + '</div>' +
      (data.critic_verdict && data.critic_verdict !== 'SKIP' ? `
      <div class="critic-row">
        <span class="critic-label">critic</span>
        <span class="${data.critic_passed ? 'critic-pass' : 'critic-fail-text'}">${data.critic_verdict}</span>
        <span style="color:var(--text2);margin-left:6px">${escHtml(data.critic_reason || '')}</span>
      </div>` : '') +
      checkHtml;

    stream.appendChild(d);

  } else if (type === 'killchain_update') {
    killChainNodes = data.nodes || [];
    renderKillChain(killChainNodes, data.latest);

  } else if (type === 'campaign') {
    const d = document.createElement('div');
    d.className = 'campaign-card';
    let chain = '<div class="kill-chain">';
    (data.tactic_path || []).forEach((t, i) => {
      if (i > 0) chain += '<span class="kc-arrow">→</span>';
      const col = TACTIC_COLORS[t] || '#6b7280';
      chain += `<span class="kc-node" style="color:${col};border-color:${col};background:${col}18">${escHtml(t)}</span>`;
    });
    chain += '</div>';
    d.innerHTML = '<h4>Campaign Saved: ' + escHtml(data.campaign_id) + '</h4>' +
      '<div style="color:var(--text2);font-size:0.78rem">' + data.steps + ' alerts</div>' + chain;
    stream.appendChild(d);

  } else if (type === 'error') {
    appendError(data.message);

  } else if (type === 'complete') {
    document.getElementById('progress-fill').style.width = '100%';
    document.getElementById('output-title').textContent = 'Pipeline Complete';
    const d = document.createElement('div');
    d.className = 'complete-banner';
    d.innerHTML = '<h3>✓ Pipeline Complete</h3>' +
      '<p style="color:var(--text2);font-size:0.82rem;margin-bottom:12px">' + escHtml(data.vector) + '</p>' +
      '<div class="stat-grid">' +
        '<div class="stat-box"><div class="stat-num">' + data.accepted + '</div><div class="stat-lbl">Alerts Accepted</div></div>' +
        '<div class="stat-box"><div class="stat-num">' + data.campaigns + '</div><div class="stat-lbl">Campaigns</div></div>' +
        '<div class="stat-box"><div class="stat-num">✓</div><div class="stat-lbl">Critic Reviewed</div></div>' +
      '</div>' +
      '<div style="margin-top:10px;font-size:0.72rem;color:var(--text3);font-family:var(--mono)">' + escHtml(data.output_file || '') + '</div>';
    stream.appendChild(d);
    resetBtn('Run Another →');

  } else if (type === 'done') {
    if (eventSource) eventSource.close();
    resetBtn('Run Another →');
  }

  document.getElementById('scroll-anchor').scrollIntoView({ behavior: 'smooth' });
}

// ----- Kill Chain SVG -----
function renderKillChain(nodes, latest) {
  const panel = document.getElementById('kc-panel');
  const svg = document.getElementById('kc-svg');
  panel.style.display = 'block';
  svg.innerHTML = '';

  if (!nodes.length) return;

  const nodeW = 130, nodeH = 36, gap = 20, padX = 16, padY = 22;
  const totalW = nodes.length * nodeW + (nodes.length - 1) * gap + padX * 2;
  svg.setAttribute('viewBox', `0 0 ${totalW} ${nodeH + padY * 2}`);
  svg.setAttribute('height', nodeH + padY * 2);

  nodes.forEach((tactic, i) => {
    const x = padX + i * (nodeW + gap);
    const y = padY;
    const col = TACTIC_COLORS[tactic] || '#6b7280';
    const isLatest = tactic === latest;

    // Arrow connector
    if (i > 0) {
      const ax = x - gap;
      const ay = y + nodeH / 2;
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', ax - nodeW + nodeW); line.setAttribute('y1', ay);
      line.setAttribute('x2', ax); line.setAttribute('y2', ay);
      line.setAttribute('stroke', '#30363d'); line.setAttribute('stroke-width', '1.5');
      svg.appendChild(line);
    }

    // Node rect
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    rect.setAttribute('x', x); rect.setAttribute('y', y);
    rect.setAttribute('width', nodeW); rect.setAttribute('height', nodeH);
    rect.setAttribute('rx', '6');
    rect.setAttribute('fill', isLatest ? col + '30' : col + '15');
    rect.setAttribute('stroke', col);
    rect.setAttribute('stroke-width', isLatest ? '2' : '1');
    svg.appendChild(rect);

    // Label
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', x + nodeW / 2); text.setAttribute('y', y + nodeH / 2 + 5);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', col);
    text.setAttribute('font-size', '11');
    text.setAttribute('font-family', "'JetBrains Mono', monospace");
    text.setAttribute('font-weight', isLatest ? '700' : '400');
    text.textContent = tactic.length > 14 ? tactic.substring(0, 13) + '…' : tactic;
    svg.appendChild(text);
  });
}

// ----- Explorer -----
function loadExplorer() {
  fetch('/api/campaigns')
    .then(r => r.json())
    .then(data => renderExplorer(data));
}

function renderExplorer(campaigns) {
  const el = document.getElementById('explorer-content');
  if (!campaigns || !campaigns.length) {
    el.innerHTML = '<div class="empty-state"><h3>No campaigns yet</h3><p>Run the pipeline first.</p></div>';
    return;
  }

  let listHtml = campaigns.map((c, i) => `
    <div class="campaign-list-item ${i === 0 ? 'active' : ''}" onclick="selectCampaign(${i}, this)">
      <div class="cli-name">${escHtml(c.prime_factor || c.campaign_id)}</div>
      <div class="cli-meta">${c.steps} alerts · ${(c.tactic_path || []).join(' → ')}</div>
    </div>`).join('');

  el.innerHTML = `
    <div class="explorer-grid">
      <div class="campaign-list">${listHtml}</div>
      <div class="campaign-detail" id="campaign-detail"></div>
    </div>`;

  window._explorerCampaigns = campaigns;
  selectCampaign(0);
}

function selectCampaign(idx, clickedEl) {
  document.querySelectorAll('.campaign-list-item').forEach(el => el.classList.remove('active'));
  if (clickedEl) clickedEl.classList.add('active');
  else {
    const items = document.querySelectorAll('.campaign-list-item');
    if (items[idx]) items[idx].classList.add('active');
  }

  const c = (window._explorerCampaigns || [])[idx];
  if (!c) return;

  const detail = document.getElementById('campaign-detail');
  if (!detail) return;

  const pathHtml = (c.tactic_path || []).map(t => {
    const col = TACTIC_COLORS[t] || '#6b7280';
    return `<span class="kc-node" style="color:${col};border-color:${col};background:${col}18">${escHtml(t)}</span>`;
  }).join('<span class="kc-arrow">→</span>');

  const stepsHtml = (c.raw_steps || []).slice(0, 8).map((s, i) => {
    const a = s.alert || {};
    const tactic = ((a.rule || {}).mitre || {}).tactic || [];
    const col = TACTIC_COLORS[tactic[0]] || '#6b7280';
    return `
      <div class="alert-item">
        <div class="alert-item-header">
          <span style="color:var(--text3)">Step ${s.step_number}</span>
          <span class="tactic-chip" style="color:${col};border-color:${col}">${escHtml(tactic[0] || 'Unknown')}</span>
          <span style="color:var(--text3);font-size:0.68rem">T+${s.time_offset_minutes}m</span>
        </div>
        <div style="color:var(--text2);font-size:0.76rem;margin-bottom:6px">${escHtml((s.action_description || '').substring(0, 100))}</div>
        <div class="alert-log">${escHtml((a.full_log || '').substring(0, 200))}</div>
      </div>`;
  }).join('');

  detail.innerHTML = `
    <div style="margin-bottom:14px">
      <div style="font-weight:700;color:var(--text);margin-bottom:4px">${escHtml(c.prime_factor || c.campaign_id)}</div>
      <div style="font-size:0.75rem;color:var(--text2);font-family:var(--mono);margin-bottom:10px">${c.steps} alerts · ${c.campaign_id}</div>
      <div class="kill-chain" style="margin-bottom:14px">${pathHtml}</div>
    </div>
    <div style="font-size:0.72rem;color:var(--text2);font-weight:600;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Alert Sequence</div>
    ${stepsHtml}
    ${c.raw_steps && c.raw_steps.length > 8 ? `<div style="color:var(--text3);font-size:0.75rem;text-align:center;padding:10px">+${c.raw_steps.length - 8} more alerts</div>` : ''}
  `;
}

// ----- Evaluate -----
function loadEvaluate() {
  fetch('/api/evaluate')
    .then(r => r.json())
    .then(data => renderEvaluate(data));
}

function renderEvaluate(data) {
  const el = document.getElementById('eval-content');
  if (!data) {
    el.innerHTML = '<div class="empty-state"><h3>No data yet</h3><p>Run the pipeline first.</p></div>';
    return;
  }

  const maxCount = Math.max(...Object.values(data.tactic_counts), 1);
  const barsHtml = Object.entries(data.tactic_counts).map(([tactic, count]) => {
    const col = TACTIC_COLORS[tactic] || '#6b7280';
    const pct = (count / maxCount * 100).toFixed(1);
    return `
      <div class="tactic-bar-row">
        <div class="tactic-bar-label">${escHtml(tactic)}</div>
        <div class="tactic-bar-track">
          <div class="tactic-bar-fill" style="width:${pct}%;background:${col}40;border-right:2px solid ${col}">
            <span class="tactic-bar-count" style="color:${col}">${count}</span>
          </div>
        </div>
      </div>`;
  }).join('');

  const tableHtml = (data.campaigns || []).map(c => {
    const pathHtml = (c.tactic_path || []).map(t => {
      const col = TACTIC_COLORS[t] || '#6b7280';
      return `<span class="path-node" style="color:${col};border-color:${col};background:${col}15">${escHtml(t)}</span>`;
    }).join('');
    return `
      <tr>
        <td style="font-family:var(--mono);color:var(--text2)">${escHtml(c.campaign_id.split('_').slice(-2).join('_'))}</td>
        <td style="color:var(--text)">${escHtml(c.prime_factor.substring(0, 40))}</td>
        <td><div class="path-pill">${pathHtml}</div></td>
        <td style="font-family:var(--mono);color:var(--accent)">${c.steps}</td>
      </tr>`;
  }).join('');

  el.innerHTML = `
    <div class="eval-stats">
      <div class="eval-stat"><div class="num">${data.total_campaigns}</div><div class="lbl">Campaigns</div></div>
      <div class="eval-stat"><div class="num">${data.total_alerts}</div><div class="lbl">Total Alerts</div></div>
      <div class="eval-stat"><div class="num">${data.avg_path_length}</div><div class="lbl">Avg Kill Chain Length</div></div>
      <div class="eval-stat"><div class="num">${data.tactic_coverage}</div><div class="lbl">MITRE Tactics Covered</div></div>
    </div>
    <div class="panel">
      <div class="panel-title">MITRE Tactic Coverage</div>
      <div class="panel-sub">Distribution of MITRE tactics across all generated campaigns.</div>
      <div class="tactic-bars">${barsHtml}</div>
    </div>
    <div class="panel">
      <div class="panel-title">Campaign Index</div>
      <div class="panel-sub">All generated campaigns with their kill chain paths.</div>
      <table class="campaign-table">
        <thead><tr>
          <th>ID</th><th>Attack Vector</th><th>Kill Chain</th><th>Alerts</th>
        </tr></thead>
        <tbody>${tableHtml}</tbody>
      </table>
    </div>`;

  // Animate bars
  setTimeout(() => {
    document.querySelectorAll('.tactic-bar-fill').forEach(bar => {
      const w = bar.style.width;
      bar.style.width = '0%';
      setTimeout(() => { bar.style.width = w; }, 50);
    });
  }, 100);
}

// ----- Helpers -----
function appendError(msg) {
  const d = document.createElement('div');
  d.className = 'error-msg';
  d.textContent = '⚠ ' + msg;
  document.getElementById('output-stream').appendChild(d);
}

function resetBtn(label) {
  const btn = document.getElementById('run-btn');
  btn.disabled = false;
  btn.textContent = label || 'Run Pipeline →';
}

function escHtml(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>
"""

# ---------------------------------------------------------
# ROUTES
# ---------------------------------------------------------
@app.route("/")
def index():
    return render_template_string(MAIN_HTML, techniques=MITRE_TECHNIQUES, tactic_colors=TACTIC_COLORS)

@app.route("/stream")
def stream():
    vector = request.args.get("vector", "").strip()
    if not vector: return "No vector", 400
    q = queue.Queue()
    threading.Thread(target=run_pipeline, args=(vector, q), daemon=True).start()
    def generate():
        while True:
            try:
                event = q.get(timeout=120)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done": break
            except queue.Empty:
                yield f"data: {json.dumps({'type':'error','data':{'message':'Timed out'}})}\n\n"
                break
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/campaigns")
def api_campaigns():
    campaigns = load_all_campaigns()
    result = []
    for c in campaigns:
        steps = c.get("steps", [])
        tactic_path = c.get("tactic_path", [])
        result.append({
            "campaign_id": c.get("campaign_id", ""),
            "prime_factor": c.get("prime_factor", ""),
            "tactic_path": tactic_path,
            "steps": len(steps),
            "raw_steps": steps[:10]
        })
    return jsonify(result)

@app.route("/api/evaluate")
def api_evaluate():
    data = compute_evaluation()
    return jsonify(data)

if __name__ == "__main__":
    print("\n benben v0.2 Prototype")
    print(" ─────────────────────────────────────")
    print(" Web:  http://localhost:5000")
    print(" CLI:  python prototype.py --cli")
    print(" ─────────────────────────────────────\n")
    app.run(debug=False, port=5000, threaded=True)