import os
import glob
import pickle
import pandas as pd
from vllm import LLM, SamplingParams
from vllm.lora.request import LoRARequest
from sklearn.metrics import classification_report, accuracy_score

class CommonsEvaluator:
    def __init__(self, base_model_id="Qwen/Qwen2.5-1.5B-Instruct", lora_path=None, output_dir="results"):
        self.base_model_id = base_model_id
        self.lora_path = lora_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        print(f"Loading vLLM Engine with base model: {self.base_model_id}...")
        # Initialize the high-throughput vLLM engine
        self.llm = LLM(
            model=self.base_model_id,
            enable_lora=(self.lora_path is not None),
            max_model_len=4096,
            gpu_memory_utilization=0.85
        )
        
        # Zero-temperature for deterministic, objective grading
        self.sampling_params = SamplingParams(
            temperature=0.0, 
            max_tokens=50 # We only need the MITRE tactic name
        )

    def load_test_data(self, tsv_filepath: str):
        """Loads the cartography TSV answer key."""
        print(f"Loading ground truth answer key from {tsv_filepath}...")
        df = pd.read_csv(tsv_filepath, sep='\t')
        # Ensure we have a unique ID for checkpointing
        if 'id' not in df.columns:
            df['id'] = df.index
        return df

    def evaluate(self, df: pd.DataFrame, batch_size: int = 256):
        """Runs batch inference and grades the AI SOC."""
        checkpoint_file = os.path.join(self.output_dir, "evaluation_checkpoint.pkl")
        results = []
        processed_ids = set()

        # ---------------------------------------------------------
        # 1. State Recovery (Checkpointing)
        # ---------------------------------------------------------
        if os.path.exists(checkpoint_file):
            try:
                with open(checkpoint_file, "rb") as f:
                    results = pickle.load(f)
                processed_ids = {res['id'] for res in results}
                print(f"Recovered {len(processed_ids)} completed evaluations from checkpoint.")
            except Exception as e:
                print(f"[!] Warning: Could not read checkpoint. Starting fresh. Error: {e}")

        # Filter out already processed logs
        pending_df = df[~df['id'].isin(processed_ids)]
        print(f"Total new logs to evaluate: {len(pending_df)}")

        if pending_df.empty:
            return self.generate_report(results)

        # ---------------------------------------------------------
        # 2. High-Speed vLLM Batch Injection
        # ---------------------------------------------------------
        lora_request = LoRARequest("lora_adapter", 1, self.lora_path) if self.lora_path else None
        
        prompts = []
        for _, row in pending_df.iterrows():
            # Strict prompt to prevent the model from chatting
            prompt = (
                "<|im_start|>system\nYou are a SIEM detection engine. Output ONLY the exact MITRE tactic name.<|im_end|>\n"
                f"<|im_start|>user\nAnalyze this log:\n{row['text']}<|im_end|>\n"
                "<|im_start|>assistant\n"
            )
            prompts.append(prompt)

        print(f"Injecting {len(prompts)} synthetic logs into the AI SOC...")
        outputs = self.llm.generate(
            prompts=prompts, 
            sampling_params=self.sampling_params, 
            lora_request=lora_request
        )

        # ---------------------------------------------------------
        # 3. The Auto-Grader
        # ---------------------------------------------------------
        for i, output in enumerate(outputs):
            row = pending_df.iloc[i]
            predicted_tactic = output.outputs[0].text.strip()
            ground_truth = str(row['label']).strip()
            
            # Record the exact evaluation
            result = {
                'id': row['id'],
                'log': row['text'],
                'ground_truth': ground_truth,
                'prediction': predicted_tactic,
                'is_correct': (predicted_tactic.lower() == ground_truth.lower())
            }
            results.append(result)

        # Save the final checkpoint
        with open(checkpoint_file, "wb") as f:
            pickle.dump(results, f)

        # Generate and print the math
        return self.generate_report(results)

    def generate_report(self, results: list):
        """Calculates Precision, Recall, and Accuracy against the synthetic baseline."""
        y_true = [res['ground_truth'] for res in results]
        y_pred = [res['prediction'] for res in results]

        accuracy = accuracy_score(y_true, y_pred)
        print("\n" + "="*50)
        print("🛡️ AI SOC CONTINUOUS VALIDATION REPORT 🛡️")
        print("="*50)
        print(f"Total Logs Evaluated: {len(results)}")
        print(f"Overall Accuracy:     {accuracy * 100:.2f}%\n")
        
        print("Detailed MITRE Coverage Metrics:")
        # Zero_division=0 prevents crashing if the AI completely missed a category
        report = classification_report(y_true, y_pred, zero_division=0)
        print(report)
        print("="*50)
        
        return results

# ---------------------------------------------------------
# Local Execution Block
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Initializing the Evaluation Engine...\n")
    
    # Auto-detect the latest cartography file
    search_pattern = "data/*_cartography.tsv"
    files = glob.glob(search_pattern)
    
    if not files:
        print("[!] No cartography TSV files found in data/ directory. Generate data first.")
    else:
        latest_tsv = max(files, key=os.path.getmtime)
        print(f"Targeting evaluation baseline: {latest_tsv}")
        
        # In a real run, you would point lora_path to your 'models/commons-siem-detector' folder
        evaluator = CommonsEvaluator(
            base_model_id="Qwen/Qwen2.5-1.5B-Instruct",
            lora_path=None # Test the baseline model before loading the fine-tuned adapter
        )
        
        test_data = evaluator.load_test_data(latest_tsv)
        
        # Trigger the evaluation loop
        # evaluator.evaluate(test_data)
        print("\n[NOTE] Batch Evaluation loop is commented out to prevent GPU allocation.")