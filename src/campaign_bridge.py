import os
import json
import csv
import glob

class CampaignBridge:
    """
    Converts campaign-structured JSON (output of the updated main.py) into
    a sequence TSV for training and evaluating the campaign pathfinding model.
    
    Output TSV format:
        campaign_id | alert_sequence (JSON string) | tactic_path (JSON string)
    
    This is the campaign equivalent of cartography_bridge.py — instead of
    individual [guid, text, label] rows, each row is one full attack campaign:
        - alert_sequence: ordered list of raw log strings the model reads
        - tactic_path:    ordered list of MITRE tactics (the ground truth path)
    """
    
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir

    def get_latest_campaign_dataset(self) -> str:
        """Finds the most recently generated campaign JSON in the data directory."""
        search_pattern = os.path.join(self.data_dir, "campaigns_*.json")
        files = glob.glob(search_pattern)
        
        if not files:
            raise FileNotFoundError(
                "No campaign datasets found in the data/ directory. "
                "Run main.py first to generate campaign data."
            )
        
        latest_file = max(files, key=os.path.getmtime)
        return latest_file

    def get_all_campaign_datasets(self) -> list:
        """Returns all campaign JSON files sorted by modification time (oldest first)."""
        search_pattern = os.path.join(self.data_dir, "campaigns_*.json")
        files = glob.glob(search_pattern)
        return sorted(files, key=os.path.getmtime)

    def convert_to_tsv(self, campaign_filepath: str) -> str:
        """
        Converts a campaigns JSON file into a sequence TSV.
        
        Each row represents ONE full attack campaign:
            campaign_id | alert_sequence | tactic_path
        
        alert_sequence: JSON list of raw log strings in chronological order
        tactic_path:    JSON list of MITRE tactic strings (the ground truth path)
        """
        print(f"Reading campaign dataset: {campaign_filepath}")
        
        with open(campaign_filepath, 'r') as f:
            campaigns = json.load(f)

        if not campaigns:
            print("[!] No campaigns found in file.")
            return None

        tsv_filepath = campaign_filepath.replace(".json", "_sequences.tsv")
        
        print(f"Converting {len(campaigns)} campaigns to sequence TSV format...")
        
        valid_campaigns = 0
        skipped = 0
        
        with open(tsv_filepath, 'w', newline='', encoding='utf-8') as tsvfile:
            writer = csv.writer(tsvfile, delimiter='\t')
            writer.writerow(['campaign_id', 'alert_sequence', 'tactic_path'])
            
            for campaign in campaigns:
                campaign_id = campaign.get("campaign_id", "UNKNOWN")
                tactic_path = campaign.get("tactic_path", [])
                steps = campaign.get("steps", [])
                
                # Skip campaigns with unknown or empty tactic paths
                if not tactic_path or tactic_path == ["Unknown"]:
                    print(f"   [!] Skipping {campaign_id}: no valid tactic path")
                    skipped += 1
                    continue
                
                # Skip campaigns with fewer than 2 steps (can't form a path)
                if len(steps) < 2:
                    print(f"   [!] Skipping {campaign_id}: too few steps ({len(steps)})")
                    skipped += 1
                    continue
                
                # Extract ordered raw log strings from the campaign steps
                alert_sequence = self._extract_alert_sequence(steps)
                
                if not alert_sequence:
                    print(f"   [!] Skipping {campaign_id}: could not extract alert sequence")
                    skipped += 1
                    continue
                
                # Serialize both lists as JSON strings for TSV storage
                writer.writerow([
                    campaign_id,
                    json.dumps(alert_sequence),   # List of raw log strings
                    json.dumps(tactic_path)        # List of MITRE tactic strings
                ])
                valid_campaigns += 1
                print(f"   [+] {campaign_id}: {len(alert_sequence)} alerts → {tactic_path}")
        
        print(f"\n✅ Campaign sequence file built: {tsv_filepath}")
        print(f"   Valid campaigns: {valid_campaigns} | Skipped: {skipped}")
        return tsv_filepath

    def merge_all_to_tsv(self) -> str:
        """
        Merges ALL campaign JSON files in the data directory into a single
        sequence TSV. Useful for building a large training set from multiple
        overnight runs.
        """
        all_files = self.get_all_campaign_datasets()
        
        if not all_files:
            raise FileNotFoundError("No campaign datasets found.")
        
        print(f"Merging {len(all_files)} campaign files into one master TSV...")
        
        all_campaigns = []
        for filepath in all_files:
            with open(filepath, 'r') as f:
                campaigns = json.load(f)
                all_campaigns.extend(campaigns)
        
        print(f"Total campaigns across all files: {len(all_campaigns)}")
        
        # Write to a merged temp file then convert
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        merged_json = os.path.join(self.data_dir, f"campaigns_merged_{timestamp}.json")
        
        with open(merged_json, 'w') as f:
            json.dump(all_campaigns, f, indent=2)
        
        return self.convert_to_tsv(merged_json)

    def _extract_alert_sequence(self, steps: list) -> list:
        """
        Extracts an ordered list of cleaned raw log strings from campaign steps.
        Steps are already in chronological order from the expander.
        """
        sequence = []
        for step in steps:
            alert = step.get("alert", {})
            full_log = alert.get("full_log", "").strip()
            
            # Clean newlines so the sequence stays flat
            full_log = full_log.replace('\n', ' ').replace('\r', '')
            
            if full_log:
                sequence.append(full_log)
        
        return sequence


# ---------------------------------------------------------
# Local Execution
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Initializing Campaign Bridge...\n")
    try:
        bridge = CampaignBridge()
        latest_json = bridge.get_latest_campaign_dataset()
        tsv_file = bridge.convert_to_tsv(latest_json)
        print(f"\nReady for campaign training: {tsv_file}")
    except Exception as e:
        print(f"[!] Campaign Bridge Error: {e}")