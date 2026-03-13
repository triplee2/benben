import os
import json
import time
from datetime import datetime

# Import our custom AI engines
from src.taxonomy_engine import CommonsTaxonomyEngine
from src.complexity_expander import CommonsComplexityExpander
from src.log_generator import CommonsLogGenerator

def generate_synthetic_dataset(prime_factor: str, depth: int = 1):
    print(f"🚀 Starting the Commons Engine for: '{prime_factor}'\n")
    
    taxonomy = CommonsTaxonomyEngine()
    expander = CommonsComplexityExpander()
    generator = CommonsLogGenerator()
    
    master_dataset = []
    
    print("=> [Stage 1] Generating Taxonomy Blueprints...")
    branches = taxonomy.generate_branches(prime_factor=prime_factor, depth=depth)
    
    for i, branch in enumerate(branches):
        print(f"\n   -> Processing Branch {i+1}: {branch.technique}")
        
        print("=> [Stage 2] Expanding into Attack Timeline...")
        timeline = expander.generate_timeline(technique=branch.technique, target=branch.target_asset)
        
        print(f"=> [Stage 3] Synthesizing {len(timeline)} Wazuh Logs (Throttled for API Limits)...")
        for step in timeline:
            print(f"      * Translating Step {step.step_number}: T+{step.time_offset_minutes}m")
            try:
                alert = generator.synthesize_wazuh_alert(
                    action_description=step.action_description, 
                    time_offset_minutes=step.time_offset_minutes
                )
                master_dataset.append(alert.model_dump())
                
                # THE THROTTLE: Pause for 15 seconds to stay under the 5 RPM limit
                print("        [+] Success! Sleeping for 15s to respect API speed limits...")
                time.sleep(15)
                
            except Exception as e:
                print(f"      [!] Error translating step {step.step_number}: {e}")
                # Even on an error, we pause so we don't hammer the server again instantly
                time.sleep(15) 
                
    os.makedirs("data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"data/synthetic_dataset_{timestamp}.json"
    
    with open(filename, "w") as f:
        json.dump(master_dataset, f, indent=2)
        
    print(f"\n✅ Pipeline Complete! {len(master_dataset)} logs successfully saved to {filename}")

if __name__ == "__main__":
    test_objective = "Data Exfiltration via Cloud Storage (e.g., AWS S3 or Google Drive)"
    try:
        generate_synthetic_dataset(prime_factor=test_objective, depth=1)
    except Exception as e:
        print(f"\n[!] Master Orchestrator Error: {e}")