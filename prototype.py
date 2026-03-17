"""
benben Prototype
================
A real prototype that runs the actual pipeline.

Web mode:  python prototype.py
CLI mode:  python prototype.py --cli

The web UI lets you pick a MITRE ATT&CK technique, then streams
the live pipeline output (taxonomy -> expander -> logs -> campaign)
directly to your browser in real time.
"""

import os
import sys
import json
import time
import queue
import threading
import argparse
import glob
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------
# CLI vs Web mode
# ---------------------------------------------------------
parser = argparse.ArgumentParser()
parser.add_argument("--cli", action="store_true", help="Run in terminal mode")
parser.add_argument("--vector", type=str, help="Attack vector for CLI mode")
args = parser.parse_args()

# ---------------------------------------------------------
# MITRE ATT&CK techniques available in prototype
# ---------------------------------------------------------
MITRE_TECHNIQUES = [
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "example": "LSASS Memory Dumping via ProcDump"
    },
    {
        "id": "T1558",
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access",
        "example": "Kerberoasting Service Account Tickets"
    },
    {
        "id": "T1053",
        "name": "Scheduled Task / Job",
        "tactic": "Persistence",
        "example": "Scheduled Task Creation for Malicious Payload"
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "example": "SSH Authorized_Keys Manipulation"
    },
    {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "example": "Disabling Windows Defender via PowerShell"
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "example": "Clearing Windows Event Logs via wevtutil"
    },
    {
        "id": "T1550",
        "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement",
        "example": "Pass the Hash via WMI"
    },
    {
        "id": "T1569",
        "name": "System Services",
        "tactic": "Execution",
        "example": "Remote Execution via PsExec"
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "example": "Data Exfiltration over DNS Tunneling"
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "example": "Ransomware Encryption of Local User Files"
    },
]

# ---------------------------------------------------------
# Pipeline runner (shared between CLI and web)
# ---------------------------------------------------------
def run_pipeline(vector: str, event_queue: queue.Queue = None):
    """
    Runs the real benben pipeline for a given attack vector.
    Sends structured events to event_queue for streaming,
    or prints directly if event_queue is None (CLI mode).
    """
    def emit(event_type: str, data: dict):
        data["timestamp"] = datetime.now().strftime("%H:%M:%S")
        if event_queue:
            event_queue.put({"type": event_type, "data": data})
        else:
            # CLI fallback — print structured output
            if event_type == "stage":
                print(f"\n{'='*60}")
                print(f"[{data['timestamp']}] {data['title']}")
                print(f"{'='*60}")
            elif event_type == "info":
                print(f"  → {data['message']}")
            elif event_type == "branch":
                print(f"\n  Branch {data['index']}: {data['technique']}")
                print(f"  Target: {data['target']}")
            elif event_type == "step":
                print(f"  Step {data['step_number']} (T+{data['time_offset']}m): {data['action'][:80]}")
            elif event_type == "alert":
                print(f"  [{data['status']}] {data['tactic']} | similarity={data['similarity']:.2f}")
                if data['status'] == 'ACCEPTED':
                    print(f"    Rule: {data['rule_desc'][:60]}")
            elif event_type == "campaign":
                print(f"\n  Campaign saved: {data['campaign_id']}")
                print(f"  Kill chain: {' → '.join(data['tactic_path'])}")
            elif event_type == "complete":
                print(f"\n{'='*60}")
                print(f"PIPELINE COMPLETE")
                print(f"  Alerts accepted: {data['accepted']}")
                print(f"  Campaigns saved: {data['campaigns']}")
                print(f"  Output: {data['output_file']}")
                print(f"{'='*60}\n")
            elif event_type == "error":
                print(f"  [ERROR] {data['message']}")

    try:
        from src.taxonomy_engine import CommonsTaxonomyEngine
        from src.complexity_expander import CommonsComplexityExpander
        from src.log_generator import CommonsLogGenerator
        from src.diversity_analyzer import CommonsDiversityAnalyzer
    except ImportError as e:
        emit("error", {"message": f"Import error: {e}"})
        emit("done", {})
        return

    # ---- Stage 1: Taxonomy ----
    emit("stage", {
        "title": "STAGE 1 — Generating Attack Taxonomy",
        "description": f"Expanding '{vector}' into specific attack branches via Gemini"
    })

    try:
        taxonomy = CommonsTaxonomyEngine()
        emit("info", {"message": "Calling Gemini taxonomy engine..."})
        branches = taxonomy.generate_branches(prime_factor=vector, depth=2)
        emit("info", {"message": f"Generated {len(branches)} attack branches"})
    except Exception as e:
        emit("error", {"message": f"Taxonomy failed: {e}"})
        emit("done", {})
        return

    for i, branch in enumerate(branches, 1):
        emit("branch", {
            "index": i,
            "technique": branch.technique,
            "target": branch.target_asset,
            "category": branch.category,
            "description": branch.description
        })

    # ---- Stage 2 + 3: Expand + Synthesize ----
    emit("stage", {
        "title": "STAGE 2 & 3 — Timeline Expansion + Log Synthesis",
        "description": "Each branch becomes a multi-step attack timeline, then Wazuh alerts"
    })

    expander = CommonsComplexityExpander()
    generator = CommonsLogGenerator()
    analyzer  = CommonsDiversityAnalyzer()

    master_dataset = []
    campaigns      = []
    embedding_vault = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    accepted_total = 0

    for i, branch in enumerate(branches):
        emit("info", {"message": f"Expanding Branch {i+1}: {branch.technique}"})

        try:
            timeline = expander.generate_timeline(
                technique=branch.technique,
                target=branch.target_asset
            )
        except Exception as e:
            emit("error", {"message": f"Expander failed on branch {i+1}: {e}"})
            continue

        emit("info", {"message": f"Timeline has {len(timeline)} steps — synthesizing logs..."})

        campaign_steps = []

        for step in timeline:
            emit("step", {
                "step_number": step.step_number,
                "time_offset": step.time_offset_minutes,
                "action": step.action_description
            })

            try:
                alert = generator.synthesize_wazuh_alert(
                    action_description=step.action_description,
                    time_offset_minutes=step.time_offset_minutes
                )

                new_embedding = analyzer.get_embedding(alert.full_log)

                # Diversity gate
                is_unique = True
                similarity_score = 0.0
                for past_embedding in embedding_vault:
                    score = analyzer.calculate_similarity(new_embedding, past_embedding)
                    if score >= 0.90:
                        is_unique = False
                        similarity_score = score
                        break
                    similarity_score = max(similarity_score, score)

                tactic = "Unknown"
                mitre = alert.rule.mitre
                if mitre and mitre.tactic:
                    tactic = mitre.tactic[0]

                if is_unique:
                    accepted_total += 1
                    alert_dict = alert.model_dump()
                    master_dataset.append(alert_dict)
                    embedding_vault.append(new_embedding)
                    campaign_steps.append({
                        "step_number": step.step_number,
                        "time_offset_minutes": step.time_offset_minutes,
                        "action_description": step.action_description,
                        "alert": alert_dict
                    })
                    emit("alert", {
                        "status": "ACCEPTED",
                        "tactic": tactic,
                        "similarity": similarity_score,
                        "rule_desc": alert.rule.description,
                        "rule_level": alert.rule.level,
                        "log_preview": alert.full_log[:100]
                    })
                else:
                    emit("alert", {
                        "status": "REJECTED",
                        "tactic": tactic,
                        "similarity": similarity_score,
                        "rule_desc": alert.rule.description,
                        "rule_level": alert.rule.level,
                        "log_preview": ""
                    })

                emit("info", {"message": "Sleeping 15s (API rate limit)..."})
                time.sleep(2)

            except Exception as e:
                emit("error", {"message": f"Step {step.step_number} failed: {e}"})
                time.sleep(2)

        # Build campaign record
        if campaign_steps:
            tactic_path = []
            for s in campaign_steps:
                t = s["alert"].get("rule", {}).get("mitre", {}) or {}
                tactics = t.get("tactic", [])
                if tactics:
                    tactic = tactics[0]
                    if not tactic_path or tactic_path[-1] != tactic:
                        tactic_path.append(tactic)

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

            emit("campaign", {
                "campaign_id": campaign["campaign_id"],
                "tactic_path": tactic_path,
                "steps": len(campaign_steps)
            })

    # ---- Stage 4: Save ----
    emit("stage", {
        "title": "STAGE 4 — Saving Outputs",
        "description": "Writing flat dataset and campaign files to disk"
    })

    os.makedirs("data", exist_ok=True)
    flat_file     = f"data/synthetic_dataset_{timestamp}.json"
    campaign_file = f"data/campaigns_{timestamp}.json"

    if master_dataset:
        with open(flat_file, "w") as f:
            json.dump(master_dataset, f, indent=2)
        emit("info", {"message": f"Flat dataset saved: {flat_file}"})

    if campaigns:
        with open(campaign_file, "w") as f:
            json.dump(campaigns, f, indent=2)
        emit("info", {"message": f"Campaign file saved: {campaign_file}"})

    emit("complete", {
        "accepted": accepted_total,
        "campaigns": len(campaigns),
        "output_file": flat_file,
        "campaign_file": campaign_file,
        "vector": vector
    })
    emit("done", {})


# ---------------------------------------------------------
# CLI MODE
# ---------------------------------------------------------
if args.cli:
    vector = args.vector
    if not vector:
        print("Available attack vectors:")
        for i, t in enumerate(MITRE_TECHNIQUES, 1):
            print(f"  {i}. [{t['id']}] {t['example']}")
        choice = input("\nPick a number (or type your own): ").strip()
        try:
            vector = MITRE_TECHNIQUES[int(choice) - 1]["example"]
        except (ValueError, IndexError):
            vector = choice

    print(f"\nRunning benben pipeline for: {vector}\n")
    run_pipeline(vector)
    sys.exit(0)


# ---------------------------------------------------------
# WEB MODE
# ---------------------------------------------------------
from flask import Flask, render_template_string, request, Response, jsonify

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>benben — AI Purple Team Platform</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  
  body {
    background: #0a0e17;
    color: #c9d1d9;
    font-family: 'Segoe UI', system-ui, sans-serif;
    min-height: 100vh;
  }

  header {
    background: #0d1117;
    border-bottom: 1px solid #21262d;
    padding: 20px 40px;
    display: flex;
    align-items: center;
    gap: 16px;
  }

  header h1 {
    font-size: 1.4rem;
    color: #58a6ff;
    font-weight: 700;
    letter-spacing: 2px;
  }

  header p {
    font-size: 0.85rem;
    color: #8b949e;
  }

  .badge {
    background: #1f2937;
    border: 1px solid #374151;
    color: #60a5fa;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
  }

  .container {
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 20px;
  }

  .panel {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 12px;
    padding: 28px;
    margin-bottom: 24px;
  }

  .panel h2 {
    font-size: 1rem;
    color: #58a6ff;
    margin-bottom: 6px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .panel p.sub {
    color: #8b949e;
    font-size: 0.85rem;
    margin-bottom: 20px;
  }

  .techniques {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
  }

  .technique-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px 16px;
    cursor: pointer;
    transition: all 0.2s;
    position: relative;
  }

  .technique-card:hover {
    border-color: #58a6ff;
    background: #1c2333;
  }

  .technique-card.selected {
    border-color: #58a6ff;
    background: #1c2333;
    box-shadow: 0 0 0 1px #58a6ff;
  }

  .technique-card .tid {
    font-size: 0.7rem;
    color: #8b949e;
    font-family: monospace;
    margin-bottom: 4px;
  }

  .technique-card .tname {
    font-size: 0.9rem;
    color: #e6edf3;
    font-weight: 600;
    margin-bottom: 4px;
  }

  .technique-card .texample {
    font-size: 0.78rem;
    color: #8b949e;
  }

  .tactic-badge {
    position: absolute;
    top: 10px;
    right: 10px;
    font-size: 0.65rem;
    padding: 2px 8px;
    border-radius: 10px;
    font-weight: 600;
  }

  .tactic-Credential.Access  { background: #2d1b1b; color: #f87171; border: 1px solid #f87171; }
  .tactic-Defense.Evasion    { background: #2a1f2d; color: #c084fc; border: 1px solid #c084fc; }
  .tactic-Persistence        { background: #1e2535; color: #818cf8; border: 1px solid #818cf8; }
  .tactic-Lateral.Movement   { background: #1e2d2a; color: #34d399; border: 1px solid #34d399; }
  .tactic-Execution          { background: #1e2535; color: #60a5fa; border: 1px solid #60a5fa; }
  .tactic-Exfiltration       { background: #2d1b1b; color: #fb923c; border: 1px solid #fb923c; }
  .tactic-Impact             { background: #2d1b1b; color: #ef4444; border: 1px solid #ef4444; }

  .custom-input {
    display: flex;
    gap: 10px;
    margin-bottom: 20px;
  }

  .custom-input input {
    flex: 1;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 10px 14px;
    color: #e6edf3;
    font-size: 0.9rem;
    outline: none;
  }

  .custom-input input:focus {
    border-color: #58a6ff;
  }

  .custom-input input::placeholder {
    color: #484f58;
  }

  .btn-run {
    background: #238636;
    color: #fff;
    border: none;
    border-radius: 8px;
    padding: 12px 28px;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
    width: 100%;
  }

  .btn-run:hover { background: #2ea043; }
  .btn-run:disabled { background: #21262d; color: #484f58; cursor: not-allowed; }

  /* Pipeline output */
  #output-panel { display: none; }

  .stage-header {
    background: #161b22;
    border-left: 3px solid #58a6ff;
    padding: 10px 16px;
    margin: 16px 0 8px;
    border-radius: 0 6px 6px 0;
    font-size: 0.9rem;
    font-weight: 600;
    color: #58a6ff;
  }

  .stage-desc {
    color: #8b949e;
    font-size: 0.8rem;
    margin-top: 2px;
  }

  .log-line {
    font-family: 'Fira Code', 'Cascadia Code', monospace;
    font-size: 0.82rem;
    padding: 3px 0;
    display: flex;
    gap: 10px;
    align-items: flex-start;
  }

  .log-line .ts { color: #484f58; min-width: 65px; }
  .log-line .msg { color: #8b949e; }

  .alert-row {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 6px 0;
    font-size: 0.82rem;
  }

  .alert-row.accepted { border-left: 3px solid #3fb950; }
  .alert-row.rejected { border-left: 3px solid #f85149; opacity: 0.6; }

  .alert-status {
    font-weight: 700;
    font-size: 0.75rem;
    margin-right: 8px;
  }

  .alert-row.accepted .alert-status { color: #3fb950; }
  .alert-row.rejected .alert-status { color: #f85149; }

  .tactic-tag {
    background: #21262d;
    border-radius: 4px;
    padding: 1px 8px;
    font-size: 0.73rem;
    color: #8b949e;
    margin-right: 8px;
  }

  .branch-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 14px;
    margin: 8px 0;
  }

  .branch-card .branch-name { color: #e6edf3; font-weight: 600; margin-bottom: 4px; }
  .branch-card .branch-target { color: #8b949e; font-size: 0.8rem; }

  .campaign-card {
    background: #0f2027;
    border: 1px solid #1d6a3a;
    border-radius: 8px;
    padding: 16px;
    margin: 10px 0;
  }

  .campaign-card h4 { color: #3fb950; margin-bottom: 8px; font-size: 0.9rem; }

  .kill-chain {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: center;
    margin-top: 8px;
  }

  .kill-chain .arrow { color: #484f58; font-size: 0.8rem; }

  .tactic-node {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.78rem;
    font-weight: 600;
    border: 1px solid;
  }

  .tactic-Discovery          { background: #0e2233; color: #38bdf8; border-color: #38bdf8; }
  .tactic-Collection         { background: #2d2208; color: #fbbf24; border-color: #fbbf24; }
  .tactic-Exfiltration       { background: #2d0f0f; color: #fb923c; border-color: #fb923c; }
  .tactic-Defense.Evasion    { background: #2a1535; color: #c084fc; border-color: #c084fc; }
  .tactic-Credential.Access  { background: #2d1515; color: #f87171; border-color: #f87171; }
  .tactic-Lateral.Movement   { background: #0f2d25; color: #34d399; border-color: #34d399; }
  .tactic-Privilege.Escalation { background: #2d2208; color: #fcd34d; border-color: #fcd34d; }
  .tactic-Initial.Access     { background: #0f2d10; color: #4ade80; border-color: #4ade80; }
  .tactic-Execution          { background: #0f1d2d; color: #60a5fa; border-color: #60a5fa; }
  .tactic-Persistence        { background: #1e1535; color: #a78bfa; border-color: #a78bfa; }
  .tactic-Impact             { background: #2d0f0f; color: #ef4444; border-color: #ef4444; }
  .tactic-Unknown            { background: #1a1a1a; color: #6b7280; border-color: #6b7280; }

  .complete-banner {
    background: #0f2d1a;
    border: 1px solid #1d6a3a;
    border-radius: 10px;
    padding: 20px 24px;
    margin-top: 20px;
  }

  .complete-banner h3 { color: #3fb950; margin-bottom: 12px; font-size: 1.1rem; }

  .stat-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
    margin-top: 12px;
  }

  .stat-box {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 14px;
    text-align: center;
  }

  .stat-box .num { font-size: 2rem; font-weight: 700; color: #58a6ff; }
  .stat-box .lbl { font-size: 0.75rem; color: #8b949e; margin-top: 4px; }

  .progress-bar {
    height: 3px;
    background: #21262d;
    border-radius: 2px;
    margin: 12px 0;
    overflow: hidden;
  }

  .progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #58a6ff, #3fb950);
    border-radius: 2px;
    width: 0%;
    transition: width 0.5s ease;
  }

  #scroll-anchor { height: 1px; }

  .error-msg {
    background: #2d0f0f;
    border: 1px solid #f85149;
    border-radius: 6px;
    padding: 10px 14px;
    color: #f85149;
    font-size: 0.85rem;
    margin: 6px 0;
  }

  .sleeping-msg {
    color: #484f58;
    font-size: 0.78rem;
    font-style: italic;
    padding: 2px 0;
  }
</style>
</head>
<body>

<header>
  <div>
    <h1>benben</h1>
    <p>AI Purple Team Platform</p>
  </div>
  <span class="badge">Prototype v0.1</span>
</header>

<div class="container">

  <!-- Selection panel -->
  <div class="panel" id="selection-panel">
    <h2>Select Attack Technique</h2>
    <p class="sub">Pick a MITRE ATT&CK technique to run through the full synthetic generation pipeline.</p>

    <div class="techniques" id="technique-grid">
      {% for t in techniques %}
      <div class="technique-card" onclick="selectTechnique(this, '{{ t.example }}')"
           data-vector="{{ t.example }}">
        <div class="tid">{{ t.id }}</div>
        <div class="tname">{{ t.name }}</div>
        <div class="texample">{{ t.example }}</div>
        <span class="tactic-badge tactic-{{ t.tactic.replace(' ', '.') }}">{{ t.tactic }}</span>
      </div>
      {% endfor %}
    </div>

    <p class="sub" style="margin-bottom:10px">Or enter a custom attack vector:</p>
    <div class="custom-input">
      <input type="text" id="custom-vector"
             placeholder="e.g. Mimikatz Pass-the-Ticket Attack"
             onkeydown="if(event.key==='Enter') runPipeline()" />
    </div>

    <button class="btn-run" id="run-btn" onclick="runPipeline()" disabled>
      Run Pipeline →
    </button>
  </div>

  <!-- Output panel -->
  <div class="panel" id="output-panel">
    <h2 id="output-title">Pipeline Running</h2>
    <p class="sub" id="output-sub">Streaming live output from benben...</p>
    <div class="progress-bar"><div class="progress-fill" id="progress-fill"></div></div>
    <div id="output-stream"></div>
    <div id="scroll-anchor"></div>
  </div>

</div>

<script>
let selectedVector = null;
let eventSource = null;
let alertsAccepted = 0;
let alertsRejected = 0;
let campaignCount = 0;
let progressValue = 0;

function selectTechnique(card, vector) {
  document.querySelectorAll('.technique-card').forEach(c => c.classList.remove('selected'));
  card.classList.add('selected');
  selectedVector = vector;
  document.getElementById('custom-vector').value = '';
  document.getElementById('run-btn').disabled = false;
}

document.getElementById('custom-vector').addEventListener('input', function() {
  if (this.value.trim()) {
    document.querySelectorAll('.technique-card').forEach(c => c.classList.remove('selected'));
    selectedVector = null;
    document.getElementById('run-btn').disabled = false;
  } else {
    document.getElementById('run-btn').disabled = (selectedVector === null);
  }
});

function getVector() {
  const custom = document.getElementById('custom-vector').value.trim();
  return custom || selectedVector;
}

function runPipeline() {
  const vector = getVector();
  if (!vector) return;

  // Reset state
  alertsAccepted = 0;
  alertsRejected = 0;
  campaignCount = 0;
  progressValue = 0;

  document.getElementById('output-title').textContent = 'Pipeline Running';
  document.getElementById('output-sub').textContent = vector;
  document.getElementById('output-stream').innerHTML = '';
  document.getElementById('progress-fill').style.width = '0%';
  document.getElementById('output-panel').style.display = 'block';
  document.getElementById('run-btn').disabled = true;
  document.getElementById('run-btn').textContent = 'Running...';

  document.getElementById('output-panel').scrollIntoView({ behavior: 'smooth' });

  if (eventSource) eventSource.close();

  eventSource = new EventSource('/stream?vector=' + encodeURIComponent(vector));

  eventSource.addEventListener('message', function(e) {
    const event = JSON.parse(e.data);
    handleEvent(event);
  });

  eventSource.addEventListener('error', function() {
    appendError('Connection lost. Pipeline may have finished or errored.');
    eventSource.close();
    resetBtn();
  });
}

function handleEvent(event) {
  const stream = document.getElementById('output-stream');
  const type = event.type;
  const data = event.data;

  if (type === 'stage') {
    progressValue = Math.min(progressValue + 25, 90);
    document.getElementById('progress-fill').style.width = progressValue + '%';
    const div = document.createElement('div');
    div.className = 'stage-header';
    div.innerHTML = data.title + '<div class="stage-desc">' + data.description + '</div>';
    stream.appendChild(div);

  } else if (type === 'info') {
    if (data.message.includes('Sleeping')) {
      const div = document.createElement('div');
      div.className = 'sleeping-msg';
      div.textContent = '  ⏳ ' + data.message;
      stream.appendChild(div);
    } else {
      const div = document.createElement('div');
      div.className = 'log-line';
      div.innerHTML = '<span class="ts">' + data.timestamp + '</span><span class="msg">→ ' + escHtml(data.message) + '</span>';
      stream.appendChild(div);
    }

  } else if (type === 'branch') {
    const div = document.createElement('div');
    div.className = 'branch-card';
    div.innerHTML =
      '<div class="branch-name">Branch ' + data.index + ': ' + escHtml(data.technique) + '</div>' +
      '<div class="branch-target">Target: ' + escHtml(data.target) + '</div>' +
      '<div class="branch-target" style="margin-top:4px;color:#6b7280">' + escHtml(data.description) + '</div>';
    stream.appendChild(div);

  } else if (type === 'step') {
    const div = document.createElement('div');
    div.className = 'log-line';
    div.innerHTML =
      '<span class="ts">' + data.timestamp + '</span>' +
      '<span class="msg">Step ' + data.step_number + ' (T+' + data.time_offset + 'm): ' + escHtml(data.action.substring(0, 90)) + '</span>';
    stream.appendChild(div);

  } else if (type === 'alert') {
    const accepted = data.status === 'ACCEPTED';
    if (accepted) alertsAccepted++; else alertsRejected++;
    const div = document.createElement('div');
    div.className = 'alert-row ' + (accepted ? 'accepted' : 'rejected');
    div.innerHTML =
      '<span class="alert-status">' + data.status + '</span>' +
      '<span class="tactic-tag">' + escHtml(data.tactic) + '</span>' +
      '<span style="color:#484f58;font-size:0.75rem">sim=' + data.similarity.toFixed(2) + '</span>' +
      (accepted ? '<div style="color:#8b949e;font-size:0.78rem;margin-top:4px">' + escHtml(data.rule_desc) + '</div>' : '');
    stream.appendChild(div);

  } else if (type === 'campaign') {
    campaignCount++;
    const div = document.createElement('div');
    div.className = 'campaign-card';
    let chainHtml = '<div class="kill-chain">';
    data.tactic_path.forEach((t, i) => {
      if (i > 0) chainHtml += '<span class="arrow">→</span>';
      const cls = 'tactic-' + t.replace(/ /g, '.');
      chainHtml += '<span class="tactic-node ' + cls + '">' + escHtml(t) + '</span>';
    });
    chainHtml += '</div>';
    div.innerHTML =
      '<h4>Campaign Saved: ' + escHtml(data.campaign_id) + '</h4>' +
      '<div style="color:#8b949e;font-size:0.8rem">' + data.steps + ' alerts | Kill chain:</div>' +
      chainHtml;
    stream.appendChild(div);

  } else if (type === 'error') {
    appendError(data.message);

  } else if (type === 'complete') {
    document.getElementById('progress-fill').style.width = '100%';
    document.getElementById('output-title').textContent = 'Pipeline Complete';

    const div = document.createElement('div');
    div.className = 'complete-banner';
    div.innerHTML =
      '<h3>✓ Pipeline Complete</h3>' +
      '<p style="color:#8b949e;font-size:0.85rem">Vector: ' + escHtml(data.vector) + '</p>' +
      '<div class="stat-grid">' +
        '<div class="stat-box"><div class="num">' + data.accepted + '</div><div class="lbl">Alerts Generated</div></div>' +
        '<div class="stat-box"><div class="num">' + data.campaigns + '</div><div class="lbl">Campaigns Saved</div></div>' +
        '<div class="stat-box"><div class="num">100%</div><div class="lbl">Pipeline Complete</div></div>' +
      '</div>' +
      '<div style="margin-top:12px;font-size:0.78rem;color:#484f58">Output: ' + escHtml(data.output_file) + '</div>';
    stream.appendChild(div);
    resetBtn('Run Another →');

  } else if (type === 'done') {
    if (eventSource) eventSource.close();
    resetBtn('Run Another →');
  }

  // Auto scroll
  document.getElementById('scroll-anchor').scrollIntoView({ behavior: 'smooth' });
}

function appendError(msg) {
  const div = document.createElement('div');
  div.className = 'error-msg';
  div.textContent = '⚠ ' + msg;
  document.getElementById('output-stream').appendChild(div);
}

function resetBtn(label) {
  const btn = document.getElementById('run-btn');
  btn.disabled = false;
  btn.textContent = label || 'Run Pipeline →';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
</script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML, techniques=MITRE_TECHNIQUES)


@app.route("/stream")
def stream():
    vector = request.args.get("vector", "").strip()
    if not vector:
        return "No vector provided", 400

    q = queue.Queue()

    def run():
        run_pipeline(vector, event_queue=q)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    def generate():
        while True:
            try:
                event = q.get(timeout=120)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done":
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'error', 'data': {'message': 'Pipeline timed out'}})}\n\n"
                break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    print("\n benben Prototype")
    print(" ─────────────────────────────────────────")
    print(" Web UI:  http://localhost:5000")
    print(" CLI:     python prototype.py --cli")
    print(" ─────────────────────────────────────────\n")
    app.run(debug=False, port=5000, threaded=True)