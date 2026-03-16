import os
import json
import glob
import pickle
import numpy as np
import pandas as pd
from vllm import LLM, SamplingParams
from vllm.lora.request import LoRARequest
from sklearn.metrics import classification_report, accuracy_score

# MITRE ATT&CK tactic order — used for DTW index conversion
MITRE_TACTIC_INDEX = {
    "Reconnaissance": 0,
    "Resource Development": 1,
    "Initial Access": 2,
    "Execution": 3,
    "Persistence": 4,
    "Privilege Escalation": 5,
    "Defense Evasion": 6,
    "Credential Access": 7,
    "Discovery": 8,
    "Lateral Movement": 9,
    "Collection": 10,
    "Command and Control": 11,
    "Exfiltration": 12,
    "Impact": 13,
    "Unknown": 14
}

# ---------------------------------------------------------
# DTW Implementation (ported from MapTrace)
# ---------------------------------------------------------
def calculate_dtw(s1: list, s2: list) -> tuple:
    """
    Calculates Dynamic Time Warping distance between two sequences.
    
    In MapTrace this measured spatial path accuracy on a map.
    Here it measures kill chain path accuracy — how closely the model's
    predicted tactic sequence matches the ground truth attack path.
    
    Lower DTW distance = better kill chain reconstruction.
    """
    n = len(s1)
    m = len(s2)
    
    dtw_matrix = np.full((n + 1, m + 1), float("inf"))
    dtw_matrix[0, 0] = 0
    
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = abs(s1[i-1] - s2[j-1])  # Distance between tactic indices
            last_min = min(
                dtw_matrix[i-1, j],   # Insertion
                dtw_matrix[i, j-1],   # Deletion
                dtw_matrix[i-1, j-1]  # Match
            )
            dtw_matrix[i, j] = cost + last_min
    
    distance = dtw_matrix[n, m]
    
    # Backtrack for the warping path
    path = []
    i, j = n, m
    while i > 0 and j > 0:
        path.append((i-1, j-1))
        min_idx = np.argmin([
            dtw_matrix[i-1, j],
            dtw_matrix[i, j-1],
            dtw_matrix[i-1, j-1]
        ])
        if min_idx == 0:
            i -= 1
        elif min_idx == 1:
            j -= 1
        else:
            i -= 1
            j -= 1
    path.reverse()
    
    return distance, path


def tactics_to_indices(tactic_list: list) -> list:
    """Converts a list of tactic name strings to numeric indices for DTW."""
    return [MITRE_TACTIC_INDEX.get(t, MITRE_TACTIC_INDEX["Unknown"]) for t in tactic_list]


def parse_tactic_chain(response: str) -> list:
    """
    Parses the model's tactic chain output back into a list.
    Handles both arrow-separated format: "Initial Access → Lateral Movement"
    and JSON list format: '["Initial Access", "Lateral Movement"]'
    """
    response = response.strip()
    
    # Try JSON list format first
    if response.startswith('['):
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
    
    # Try arrow-separated format
    if '→' in response:
        return [t.strip() for t in response.split('→') if t.strip()]
    
    # Try comma-separated format as fallback
    if ',' in response:
        return [t.strip() for t in response.split(',') if t.strip()]
    
    # Single tactic
    return [response] if response else ["Unknown"]


# ---------------------------------------------------------
# Main Evaluator
# ---------------------------------------------------------
class CommonsEvaluator:
    """
    Evaluates AI SOC models at two levels:
    
    Level 1 — Single-alert classification (existing):
        Scores: Precision, Recall, Accuracy per MITRE tactic
    
    Level 2 — Campaign pathfinding (new):
        Scores: DTW distance between predicted kill chain and ground truth path
                Lower is better. 0 = perfect kill chain reconstruction.
    """
    
    def __init__(
        self,
        base_model_id="Qwen/Qwen2.5-1.5B-Instruct",
        lora_path_single=None,
        lora_path_campaign=None,
        output_dir="results"
    ):
        self.base_model_id = base_model_id
        self.lora_path_single = lora_path_single
        self.lora_path_campaign = lora_path_campaign
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        print(f"Loading vLLM Engine with base model: {self.base_model_id}...")
        self.llm = LLM(
            model=self.base_model_id,
            tensor_parallel_size=max(1, __import__('torch').cuda.device_count()),
            enable_lora=(lora_path_single is not None or lora_path_campaign is not None),
            max_model_len=4096,
            enable_chunked_prefill=True,
            max_num_seqs=256,
            gpu_memory_utilization=0.85
        )
        
        # Zero-temperature for deterministic, objective grading
        self.sampling_params_single = SamplingParams(
            temperature=0.0,
            max_tokens=50       # Only need the tactic name
        )
        self.sampling_params_campaign = SamplingParams(
            temperature=0.0,
            max_tokens=150      # Full tactic chain can be longer
        )

    # ---------------------------------------------------------
    # Level 1: Single-Alert Evaluation (existing)
    # ---------------------------------------------------------
    def load_test_data(self, tsv_filepath: str) -> pd.DataFrame:
        print(f"[Single-Alert] Loading ground truth from {tsv_filepath}...")
        df = pd.read_csv(tsv_filepath, sep='\t')
        if 'id' not in df.columns:
            df['id'] = df.index
        return df

    def evaluate(self, df: pd.DataFrame, batch_size: int = 256):
        """Runs single-alert batch inference and scores against ground truth."""
        checkpoint_file = os.path.join(self.output_dir, "single_alert_checkpoint.pkl")
        results = []
        processed_ids = set()

        # State recovery
        if os.path.exists(checkpoint_file):
            try:
                with open(checkpoint_file, "rb") as f:
                    results = pickle.load(f)
                # Filter out any corrupt/invalid results on reload
                results = [r for r in results if r.get('ground_truth') and r.get('prediction')]
                processed_ids = {res['id'] for res in results}
                print(f"[Single-Alert] Recovered {len(processed_ids)} results from checkpoint.")
            except Exception as e:
                print(f"[!] Warning: Could not read checkpoint. Starting fresh. Error: {e}")

        pending_df = df[~df['id'].isin(processed_ids)]
        print(f"[Single-Alert] New logs to evaluate: {len(pending_df)}")

        if pending_df.empty:
            return self._generate_single_report(results)

        lora_request = LoRARequest("single_adapter", 1, self.lora_path_single) if self.lora_path_single else None

        prompts = []
        for _, row in pending_df.iterrows():
            prompt = (
                "<|im_start|>system\nYou are a SIEM detection engine. Output ONLY the exact MITRE tactic name.<|im_end|>\n"
                f"<|im_start|>user\nAnalyze this log:\n{row['text']}<|im_end|>\n"
                "<|im_start|>assistant\n"
            )
            prompts.append(prompt)

        print(f"[Single-Alert] Injecting {len(prompts)} logs into the AI SOC...")
        outputs = self.llm.generate(prompts, sampling_params=self.sampling_params_single, lora_request=lora_request)

        for i, output in enumerate(outputs):
            row = pending_df.iloc[i]
            predicted_tactic = output.outputs[0].text.strip()
            ground_truth = str(row['label']).strip()
            
            result = {
                'id': row['id'],
                'log': row['text'],
                'ground_truth': ground_truth,
                'prediction': predicted_tactic,
                'is_correct': (predicted_tactic.lower() == ground_truth.lower())
            }
            results.append(result)

        with open(checkpoint_file, "wb") as f:
            pickle.dump(results, f)

        return self._generate_single_report(results)

    def _generate_single_report(self, results: list):
        y_true = [res['ground_truth'] for res in results]
        y_pred = [res['prediction'] for res in results]
        accuracy = accuracy_score(y_true, y_pred)

        print("\n" + "="*60)
        print("🛡️  AI SOC — SINGLE-ALERT CLASSIFICATION REPORT  🛡️")
        print("="*60)
        print(f"Total Logs Evaluated: {len(results)}")
        print(f"Overall Accuracy:     {accuracy * 100:.2f}%\n")
        print("Detailed MITRE Coverage Metrics:")
        print(classification_report(y_true, y_pred, zero_division=0))
        print("="*60)
        return results

    # ---------------------------------------------------------
    # Level 2: Campaign Path Evaluation (new)
    # ---------------------------------------------------------
    def load_campaign_test_data(self, tsv_filepath: str) -> pd.DataFrame:
        print(f"[Campaign] Loading ground truth from {tsv_filepath}...")
        df = pd.read_csv(tsv_filepath, sep='\t')
        if 'id' not in df.columns:
            df['id'] = df.index
        return df

    def evaluate_campaigns(self, df: pd.DataFrame):
        """
        Runs campaign-level inference and scores predicted kill chain paths
        against ground truth using DTW distance.
        """
        checkpoint_file = os.path.join(self.output_dir, "campaign_checkpoint.pkl")
        results = []
        processed_ids = set()

        # State recovery — filter out results with infinite DTW (corrupt)
        if os.path.exists(checkpoint_file):
            try:
                with open(checkpoint_file, "rb") as f:
                    results = pickle.load(f)
                results = [r for r in results if r.get('dtw_distance', float('inf')) < float('inf')]
                processed_ids = {res['id'] for res in results}
                print(f"[Campaign] Recovered {len(processed_ids)} valid results from checkpoint.")
            except Exception as e:
                print(f"[!] Warning: Could not read campaign checkpoint. Starting fresh. Error: {e}")

        pending_df = df[~df['id'].isin(processed_ids)]
        print(f"[Campaign] New campaigns to evaluate: {len(pending_df)}")

        if pending_df.empty:
            return self._generate_campaign_report(results)

        lora_request = LoRARequest("campaign_adapter", 2, self.lora_path_campaign) if self.lora_path_campaign else None

        prompts = []
        ground_truths = []

        for _, row in pending_df.iterrows():
            try:
                alert_sequence = json.loads(row['alert_sequence'])
                tactic_path = json.loads(row['tactic_path'])
            except (json.JSONDecodeError, KeyError):
                continue

            numbered_alerts = "\n".join([
                f"[Alert {i+1}] {alert}"
                for i, alert in enumerate(alert_sequence)
            ])

            prompt = (
                "<|im_start|>system\n"
                "You are a SOC analyst. Given a sequence of SIEM alerts, output ONLY the "
                "ordered MITRE ATT&CK tactic chain in the format: "
                "Tactic1 → Tactic2 → Tactic3\n"
                "<|im_end|>\n"
                f"<|im_start|>user\n"
                f"Analyze this attack campaign and identify the kill chain path:\n\n"
                f"{numbered_alerts}\n"
                f"<|im_end|>\n"
                "<|im_start|>assistant\n"
            )
            prompts.append(prompt)
            ground_truths.append({
                'id': row['id'],
                'campaign_id': row.get('campaign_id', row['id']),
                'tactic_path': tactic_path
            })

        print(f"[Campaign] Evaluating {len(prompts)} campaigns...")
        outputs = self.llm.generate(prompts, sampling_params=self.sampling_params_campaign, lora_request=lora_request)

        for i, output in enumerate(outputs):
            gt = ground_truths[i]
            predicted_text = output.outputs[0].text.strip()
            predicted_path = parse_tactic_chain(predicted_text)
            ground_truth_path = gt['tactic_path']

            # Convert tactic names to indices for DTW
            pred_indices = tactics_to_indices(predicted_path)
            truth_indices = tactics_to_indices(ground_truth_path)

            # Calculate DTW distance
            try:
                dtw_distance, dtw_path = calculate_dtw(pred_indices, truth_indices)
            except Exception:
                dtw_distance = float('inf')
                dtw_path = []

            result = {
                'id': gt['id'],
                'campaign_id': gt['campaign_id'],
                'ground_truth_path': ground_truth_path,
                'predicted_path': predicted_path,
                'predicted_raw': predicted_text,
                'dtw_distance': dtw_distance,
                'path_length_truth': len(ground_truth_path),
                'path_length_predicted': len(predicted_path),
                'exact_match': (predicted_path == ground_truth_path)
            }
            results.append(result)

        with open(checkpoint_file, "wb") as f:
            pickle.dump(results, f)

        return self._generate_campaign_report(results)

    def _generate_campaign_report(self, results: list):
        if not results:
            print("[Campaign] No results to report.")
            return results

        valid = [r for r in results if r['dtw_distance'] < float('inf')]
        
        if not valid:
            print("[Campaign] No valid results (all DTW distances are infinite).")
            return results

        dtw_distances = [r['dtw_distance'] for r in valid]
        exact_matches = sum(1 for r in valid if r['exact_match'])
        
        avg_dtw = np.mean(dtw_distances)
        median_dtw = np.median(dtw_distances)
        exact_match_rate = exact_matches / len(valid) * 100

        # Normalized DTW — divide by path length for fair comparison
        normalized_dtw = [
            r['dtw_distance'] / max(r['path_length_truth'], 1)
            for r in valid
        ]
        avg_normalized_dtw = np.mean(normalized_dtw)

        print("\n" + "="*60)
        print("🗺️   AI SOC — CAMPAIGN KILL CHAIN PATHFINDING REPORT  🗺️")
        print("="*60)
        print(f"Total Campaigns Evaluated: {len(valid)}")
        print(f"Exact Kill Chain Match:    {exact_matches}/{len(valid)} ({exact_match_rate:.1f}%)")
        print(f"Average DTW Distance:      {avg_dtw:.4f}")
        print(f"Median DTW Distance:       {median_dtw:.4f}")
        print(f"Avg Normalized DTW:        {avg_normalized_dtw:.4f}  (lower = better, 0 = perfect)")
        print()
        
        # Show a few examples
        print("Sample Predictions (first 3):")
        for r in valid[:3]:
            truth_str = " → ".join(r['ground_truth_path'])
            pred_str  = " → ".join(r['predicted_path'])
            match_icon = "✅" if r['exact_match'] else "⚠️ "
            print(f"  {match_icon} Campaign: {r['campaign_id']}")
            print(f"     Truth:     {truth_str}")
            print(f"     Predicted: {pred_str}")
            print(f"     DTW:       {r['dtw_distance']:.4f}")
            print()

        print("="*60)
        return results

    # ---------------------------------------------------------
    # Run both evaluations together
    # ---------------------------------------------------------
    def evaluate_full(self, single_tsv: str, campaign_tsv: str):
        """Runs both Level 1 and Level 2 evaluations and prints combined report."""
        print("\n🚀 Running Full AI SOC Evaluation (Single-Alert + Campaign)\n")
        
        # Level 1
        single_df = self.load_test_data(single_tsv)
        self.evaluate(single_df)
        
        # Level 2
        campaign_df = self.load_campaign_test_data(campaign_tsv)
        self.evaluate_campaigns(campaign_df)


# ---------------------------------------------------------
# Local Execution Block
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Initializing the Evaluation Engine...\n")
    
    single_files = sorted(glob.glob("data/*_cartography.tsv"), key=os.path.getmtime)
    campaign_files = sorted(glob.glob("data/*_sequences.tsv"), key=os.path.getmtime)

    if not single_files and not campaign_files:
        print("[!] No evaluation data found. Run the full pipeline first.")
    else:
        evaluator = CommonsEvaluator(
            base_model_id="Qwen/Qwen2.5-1.5B-Instruct",
            lora_path_single=None,      # Point to models/commons-siem-detector after training
            lora_path_campaign=None     # Point to models/commons-campaign-pathfinder after training
        )
        
        if single_files:
            print(f"Single-alert baseline: {single_files[-1]}")
        if campaign_files:
            print(f"Campaign baseline:     {campaign_files[-1]}")
        
        # Uncomment to run:
        # if single_files and campaign_files:
        #     evaluator.evaluate_full(single_files[-1], campaign_files[-1])
        
        print("\n[NOTE] Evaluation loops are commented out to prevent GPU allocation.")