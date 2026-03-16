"""
Migration Script: Converts existing flat synthetic_dataset_*.json files
into the campaigns_*.json format expected by campaign_bridge.py.

Each synthetic_dataset file = one attack vector run = one campaign.
The alerts inside are already in chronological order from the generator.
"""

import os
import json
import glob
from datetime import datetime

# The original attack vectors in the order main.py ran them
# These map to the synthetic_dataset files in chronological order
ATTACK_VECTORS = [
    "LSASS Memory Dumping via ProcDump",
    "Kerberoasting Service Account Tickets",
    "Scheduled Task Creation for Malicious Payload",
    "SSH Authorized_Keys Manipulation",
    "Disabling Windows Defender via PowerShell",
    "Clearing Windows Event Logs via wevtutil",
    "Pass the Hash via Windows Management Instrumentation (WMI)",
    "Remote Execution via PsExec",
    "Data Exfiltration over DNS Tunneling",
    "Ransomware Encryption of Local User Files"
]


def extract_tactic_path(alerts: list) -> list:
    """
    Extracts the ordered sequence of unique MITRE tactics from a list of alerts.
    Deduplicates consecutive identical tactics.
    Uses the first tactic from each alert's mitre.tactic list.
    """
    tactic_path = []
    for alert in alerts:
        rule = alert.get("rule", {})
        mitre = rule.get("mitre", {})
        
        if mitre and "tactic" in mitre and len(mitre["tactic"]) > 0:
            tactic = mitre["tactic"][0]
            # Only append if different from the last (deduplicate consecutive)
            if not tactic_path or tactic_path[-1] != tactic:
                tactic_path.append(tactic)
    
    return tactic_path if tactic_path else ["Unknown"]


def build_campaign_steps(alerts: list) -> list:
    """
    Converts flat alerts into campaign steps with step metadata.
    Since we lost the original step numbers from the expander,
    we reconstruct them from the alert order.
    """
    steps = []
    for i, alert in enumerate(alerts):
        # Reconstruct action description from available fields
        rule_desc = alert.get("rule", {}).get("description", "Unknown action")
        cmd = alert.get("data", {}).get("command_line", "")
        
        action_description = rule_desc
        if cmd:
            action_description = f"{rule_desc} | Command: {cmd}"
        
        steps.append({
            "step_number": i + 1,
            "time_offset_minutes": i * 5,   # Approximate — original times lost
            "action_description": action_description,
            "alert": alert
        })
    
    return steps


def migrate():
    data_dir = "data"
    
    # Find all flat synthetic dataset files sorted by modification time
    pattern = os.path.join(data_dir, "synthetic_dataset_*.json")
    files = sorted(
        [f for f in glob.glob(pattern) if "_cartography" not in f],
        key=os.path.getmtime
    )
    
    if not files:
        print("[!] No synthetic_dataset_*.json files found in data/")
        return
    
    print(f"Found {len(files)} synthetic dataset files to migrate:\n")
    for f in files:
        print(f"  {f}")
    print()
    
    all_campaigns = []
    
    for i, filepath in enumerate(files):
        # Map to the attack vector by position
        vector = ATTACK_VECTORS[i] if i < len(ATTACK_VECTORS) else f"Unknown Vector {i+1}"
        
        print(f"[{i+1}/{len(files)}] Migrating: {os.path.basename(filepath)}")
        print(f"  Attack vector: {vector}")
        
        with open(filepath, 'r') as f:
            alerts = json.load(f)
        
        if not alerts:
            print(f"  [!] Empty file — skipping")
            continue
        
        # Extract the tactic path from the alerts
        tactic_path = extract_tactic_path(alerts)
        
        # Build campaign steps from the flat alerts
        steps = build_campaign_steps(alerts)
        
        # Extract timestamp from filename for campaign ID
        # e.g. synthetic_dataset_20260312_200623.json → 20260312_200623
        basename = os.path.basename(filepath)
        ts = basename.replace("synthetic_dataset_", "").replace(".json", "")
        
        campaign = {
            "campaign_id": f"{ts}_branch1",
            "prime_factor": vector,
            "branch_technique": vector,
            "branch_target": "Various targets",
            "branch_description": f"Migrated from {basename}",
            "tactic_path": tactic_path,
            "steps": steps
        }
        
        all_campaigns.append(campaign)
        
        print(f"  Alerts:      {len(alerts)}")
        print(f"  Steps built: {len(steps)}")
        print(f"  Tactic path: {' → '.join(tactic_path)}")
        print()
    
    if not all_campaigns:
        print("[!] No campaigns could be built.")
        return
    
    # Save as campaigns_migrated.json
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(data_dir, f"campaigns_migrated_{timestamp}.json")
    
    with open(output_file, 'w') as f:
        json.dump(all_campaigns, f, indent=2)
    
    print(f"✅ Migration complete!")
    print(f"   {len(all_campaigns)} campaigns saved to: {output_file}")
    print(f"\nNext step — run the campaign bridge:")
    print(f"   python src/campaign_bridge.py")


if __name__ == "__main__":
    migrate()