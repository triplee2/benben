import os
import json
import csv
import glob

class CartographyBridge:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir

    def get_latest_dataset(self) -> str:
        """Finds the most recently generated JSON dataset in the data directory."""
        search_pattern = os.path.join(self.data_dir, "synthetic_dataset_*.json")
        files = glob.glob(search_pattern)
        
        if not files:
            raise FileNotFoundError("No synthetic datasets found in the data/ directory.")
            
        # Sort by modification time to get the newest one
        latest_file = max(files, key=os.path.getmtime)
        return latest_file

    def convert_to_tsv(self, json_filepath: str):
        """
        Flattens the nested Wazuh JSON into a strict TSV format:
        [guid] \t [text] \t [label]
        """
        print(f"Reading dataset: {json_filepath}")
        
        with open(json_filepath, 'r') as f:
            alerts = json.load(f)

        tsv_filepath = json_filepath.replace(".json", "_cartography.tsv")
        
        print(f"Converting {len(alerts)} alerts to TSV format...")
        
        # Write to TSV with tab delimiter
        with open(tsv_filepath, 'w', newline='', encoding='utf-8') as tsvfile:
            writer = csv.writer(tsvfile, delimiter='\t')
            # Write the strict headers expected by AllenAI
            writer.writerow(['guid', 'text', 'label'])
            
            for alert in alerts:
                # 1. Extract the unique ID
                guid = alert.get("id", "UNKNOWN_ID")
                
                # 2. Extract the raw string the ML model needs to read
                text = alert.get("full_log", "").strip()
                # Clean out newlines so it doesn't break the TSV formatting
                text = text.replace('\n', ' ').replace('\r', '')
                
                # 3. Extract the Label (The Mitre Tactic)
                label = "Unknown"
                rule = alert.get("rule", {})
                mitre = rule.get("mitre", {})
                if mitre and "tactic" in mitre and len(mitre["tactic"]) > 0:
                    label = mitre["tactic"][0]
                
                # Write the flattened row
                writer.writerow([guid, text, label])
                
        print(f"✅ Successfully built training file: {tsv_filepath}")

# ---------------------------------------------------------
# Local Execution
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Initializing Cartography Bridge...\n")
    try:
        bridge = CartographyBridge()
        latest_json = bridge.get_latest_dataset()
        bridge.convert_to_tsv(latest_json)
    except Exception as e:
        print(f"[!] Bridge Error: {e}")