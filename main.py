import os
import json
import time
from datetime import datetime

# Import our custom AI engines
from src.taxonomy_engine import CommonsTaxonomyEngine
from src.complexity_expander import CommonsComplexityExpander
from src.log_generator import CommonsLogGenerator
from src.diversity_analyzer import CommonsDiversityAnalyzer # <-- NEW IMPORT

def generate_synthetic_dataset(prime_factor: str, depth: int = 1, similarity_threshold: float = 0.85):
    """
    The master orchestrator for the Commons pipeline.
    Flows from Blueprint -> Timeline -> Synthesis -> Quality Gate -> Disk.
    """
    print(f"🚀 Starting the Commons Engine for: '{prime_factor}'\n")
    
    # Initialize all four engines
    taxonomy = CommonsTaxonomyEngine()
    expander = CommonsComplexityExpander()
    generator = CommonsLogGenerator()
    analyzer = CommonsDiversityAnalyzer() # <-- NEW ENGINE
    
    master_dataset = []
    embedding_vault = [] # Stores mathematical vectors of accepted logs
    
    print("=> [Stage 1] Generating Taxonomy Blueprints...")
    branches = taxonomy.generate_branches(prime_factor=prime_factor, depth=depth)
    
    for i, branch in enumerate(branches):
        print(f"\n   -> Processing Branch {i+1}: {branch.technique}")
        
        print("=> [Stage 2] Expanding into Attack Timeline...")
        timeline = expander.generate_timeline(technique=branch.technique, target=branch.target_asset)
        
        print(f"=> [Stage 3 & 4] Synthesizing & Analyzing {len(timeline)} Wazuh Logs (Throttled)...")
        for step in timeline:
            print(f"\n      * Translating Step {step.step_number}: T+{step.time_offset_minutes}m")
            try:
                # 1. Synthesize the JSON alert
                alert = generator.synthesize_wazuh_alert(
                    action_description=step.action_description, 
                    time_offset_minutes=step.time_offset_minutes
                )
                
                # 2. Convert the raw Windows/Linux log string into a mathematical vector
                new_embedding = analyzer.get_embedding(alert.full_log)
                
                # 3. The Quality Gate: Compare against the vault
                is_unique = True
                for past_embedding in embedding_vault:
                    score = analyzer.calculate_similarity(new_embedding, past_embedding)
                    
                    if score >= similarity_threshold:
                        print(f"        [x] REJECTED: Semantic similarity too high ({score:.4f}). AI is repeating itself.")
                        is_unique = False
                        break # Stop checking, it failed the test
                
                # 4. Save to the dataset ONLY if it is mathematically unique
                if is_unique:
                    print(f"        [+] ACCEPTED: Log is mathematically unique!")
                    master_dataset.append(alert.model_dump())
                    embedding_vault.append(new_embedding) # Add its vector to the vault
                
                # 5. The Throttle
                print("        [zZz] Sleeping for 15s to respect API speed limits...")
                time.sleep(15)
                
            except Exception as e:
                print(f"      [!] Error on step {step.step_number}: {e}")
                time.sleep(15) 
                
    # ---------------------------------------------------------
    # STAGE 5: Save to Disk
    # ---------------------------------------------------------
    os.makedirs("data", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"data/synthetic_dataset_{timestamp}.json"
    
    # Only save if we actually got unique logs
    if master_dataset:
        with open(filename, "w") as f:
            json.dump(master_dataset, f, indent=2)
        print(f"\n✅ Pipeline Complete! {len(master_dataset)} highly diverse logs successfully saved to {filename}")
    else:
        print("\n⚠️ Pipeline Complete, but 0 logs passed the quality gate. Try a different prime factor.")

if __name__ == "__main__":
    # Let's test it with a totally new attack vector
    test_objective = "Privilege Escalation via Windows Token Manipulation"
    
    try:
        generate_synthetic_dataset(prime_factor=test_objective, depth=1, similarity_threshold=0.85)
    except Exception as e:
        print(f"\n[!] Master Orchestrator Error: {e}")