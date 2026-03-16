import os
import json
import time
from datetime import datetime

# Import our custom AI engines
from src.taxonomy_engine import CommonsTaxonomyEngine
from src.complexity_expander import CommonsComplexityExpander
from src.log_generator import CommonsLogGenerator
from src.diversity_analyzer import CommonsDiversityAnalyzer

def generate_synthetic_dataset(prime_factor: str, depth: int = 1, similarity_threshold: float = 0.85):
    """
    The master orchestrator for the Commons pipeline.
    Flows from Blueprint -> Timeline -> Synthesis -> Quality Gate -> Disk.
    
    Saves TWO outputs:
    1. data/synthetic_dataset_{timestamp}.json  — flat alert list (single-alert pipeline)
    2. data/campaigns_{timestamp}.json          — campaign groups (campaign pipeline)
    """
    print(f"🚀 Starting the Commons Engine for: '{prime_factor}'\n")
    
    # Initialize all four engines
    taxonomy = CommonsTaxonomyEngine()
    expander = CommonsComplexityExpander()
    generator = CommonsLogGenerator()
    analyzer = CommonsDiversityAnalyzer()
    
    master_dataset = []     # Flat alert list — feeds existing single-alert pipeline
    campaigns = []          # Campaign groups — feeds new campaign pipeline
    embedding_vault = []    # Stores mathematical vectors of accepted logs
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    print("=> [Stage 1] Generating Taxonomy Blueprints...")
    branches = taxonomy.generate_branches(prime_factor=prime_factor, depth=depth)
    
    for i, branch in enumerate(branches):
        print(f"\n   -> Processing Branch {i+1}: {branch.technique}")
        
        print("=> [Stage 2] Expanding into Attack Timeline...")
        timeline = expander.generate_timeline(technique=branch.technique, target=branch.target_asset)
        
        print(f"=> [Stage 3 & 4] Synthesizing & Analyzing {len(timeline)} Wazuh Logs (Throttled)...")
        
        # Track alerts for this specific campaign (branch + timeline)
        campaign_steps = []
        
        for step in timeline:
            print(f"\n      * Translating Step {step.step_number}: T+{step.time_offset_minutes}m")
            try:
                # 1. Synthesize the JSON alert
                alert = generator.synthesize_wazuh_alert(
                    action_description=step.action_description, 
                    time_offset_minutes=step.time_offset_minutes
                )
                
                # 2. Convert the raw log string into a mathematical vector
                new_embedding = analyzer.get_embedding(alert.full_log)
                
                # 3. The Quality Gate: Compare against the vault
                is_unique = True
                for past_embedding in embedding_vault:
                    score = analyzer.calculate_similarity(new_embedding, past_embedding)
                    
                    if score >= similarity_threshold:
                        print(f"        [x] REJECTED: Semantic similarity too high ({score:.4f}). AI is repeating itself.")
                        is_unique = False
                        break
                
                # 4. Save ONLY if mathematically unique
                if is_unique:
                    print(f"        [+] ACCEPTED: Log is mathematically unique!")
                    alert_dict = alert.model_dump()
                    
                    # Add to flat list (existing pipeline)
                    master_dataset.append(alert_dict)
                    
                    # Add to campaign steps (new pipeline) — preserving order and step metadata
                    campaign_steps.append({
                        "step_number": step.step_number,
                        "time_offset_minutes": step.time_offset_minutes,
                        "action_description": step.action_description,
                        "alert": alert_dict
                    })
                    
                    embedding_vault.append(new_embedding)
                
                # 5. Throttle
                print("        [zZz] Sleeping for 15s to respect API speed limits...")
                time.sleep(15)
                
            except Exception as e:
                print(f"      [!] Error on step {step.step_number}: {e}")
                time.sleep(15)
        
        # ---------------------------------------------------------
        # Build the campaign record for this branch
        # Extract the tactic path from the ordered accepted alerts
        # ---------------------------------------------------------
        if campaign_steps:
            tactic_path = _extract_tactic_path(campaign_steps)
            
            campaign = {
                "campaign_id": f"{timestamp}_branch{i+1}",
                "prime_factor": prime_factor,
                "branch_technique": branch.technique,
                "branch_target": branch.target_asset,
                "branch_description": branch.description,
                "tactic_path": tactic_path,   # The ground truth path for evaluation
                "steps": campaign_steps        # Ordered alerts with step metadata
            }
            campaigns.append(campaign)
            print(f"\n   ✅ Campaign recorded: {len(campaign_steps)} steps | Tactic path: {tactic_path}")
        else:
            print(f"\n   ⚠️ Branch {i+1} produced 0 unique logs — skipping campaign record.")
                
    # ---------------------------------------------------------
    # STAGE 5: Save to Disk
    # ---------------------------------------------------------
    os.makedirs("data", exist_ok=True)
    
    # Output 1: Flat alert list (feeds existing cartography_bridge -> commons_forge -> evaluator)
    flat_filename = f"data/synthetic_dataset_{timestamp}.json"
    if master_dataset:
        with open(flat_filename, "w") as f:
            json.dump(master_dataset, f, indent=2)
        print(f"\n✅ Flat dataset saved: {len(master_dataset)} alerts → {flat_filename}")
    else:
        print("\n⚠️ 0 alerts passed the quality gate.")
    
    # Output 2: Campaign groups (feeds new campaign_bridge -> campaign training -> DTW evaluator)
    campaign_filename = f"data/campaigns_{timestamp}.json"
    if campaigns:
        with open(campaign_filename, "w") as f:
            json.dump(campaigns, f, indent=2)
        print(f"✅ Campaign dataset saved: {len(campaigns)} campaigns → {campaign_filename}")
    else:
        print("⚠️ 0 campaigns recorded.")
    
    return flat_filename, campaign_filename


def _extract_tactic_path(campaign_steps: list) -> list:
    """
    Extracts the ordered sequence of unique MITRE tactics from campaign steps.
    Deduplicates consecutive identical tactics (e.g. two Lateral Movement steps
    become one Lateral Movement node in the path).
    """
    tactic_path = []
    for step in campaign_steps:
        alert = step.get("alert", {})
        rule = alert.get("rule", {})
        mitre = rule.get("mitre", {})
        
        if mitre and "tactic" in mitre and len(mitre["tactic"]) > 0:
            tactic = mitre["tactic"][0]
            # Only append if different from the last tactic (dedup consecutive)
            if not tactic_path or tactic_path[-1] != tactic:
                tactic_path.append(tactic)
    
    return tactic_path if tactic_path else ["Unknown"]


if __name__ == "__main__":
    # The Overnight Batch Target List
    attack_vectors = [
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
    
    print(f"🌟 INITIATING OVERNIGHT BATCH RUN: {len(attack_vectors)} Vectors Queued 🌟\n")
    
    for i, vector in enumerate(attack_vectors):
        print(f"==================================================")
        print(f"[{i+1}/{len(attack_vectors)}] PROCESSING: {vector}")
        print(f"==================================================")
        try:
            flat_file, campaign_file = generate_synthetic_dataset(
                prime_factor=vector,
                depth=1,
                similarity_threshold=0.90
            )
            print(f"\n[BATCH MANAGER] Attack complete.")
            print(f"  Flat data  → {flat_file}")
            print(f"  Campaigns  → {campaign_file}")
            print("[BATCH MANAGER] Cooling down for 30s before the next vector...\n")
            time.sleep(30)
            
        except Exception as e:
            print(f"\n[!] BATCH MANAGER ERROR on '{vector}': {e}")
            print("[BATCH MANAGER] Skipping to next vector in 30s...\n")
            time.sleep(30)
            
    print("🏁 BATCH RUN FINISHED!")