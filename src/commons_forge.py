import os
import json
import glob
import pandas as pd
import torch
from datasets import Dataset
from peft import LoraConfig
from trl import SFTTrainer, SFTConfig
from transformers import AutoModelForCausalLM, AutoTokenizer

class CommonsForge:
    """
    Fine-tunes Qwen2.5-1.5B-Instruct using LoRA for SIEM detection.
    
    Supports two training modes that run in parallel:
    
    Mode 1 — Single-alert classification (existing):
        Input:  One raw SIEM log
        Output: The MITRE tactic label
    
    Mode 2 — Campaign pathfinding (new):
        Input:  Ordered sequence of raw SIEM logs from one attack campaign
        Output: The ordered list of MITRE tactics (the kill chain path)
    """
    
    def __init__(
        self,
        model_id="Qwen/Qwen2.5-1.5B-Instruct",
        output_dir_single="models/commons-siem-detector",
        output_dir_campaign="models/commons-campaign-pathfinder"
    ):
        self.model_id = model_id
        self.output_dir_single = output_dir_single
        self.output_dir_campaign = output_dir_campaign

    # ---------------------------------------------------------
    # MODE 1: Single-Alert Dataset (existing)
    # ---------------------------------------------------------
    def prepare_dataset(self, tsv_filepath: str) -> Dataset:
        """
        Converts the Cartography TSV into TRL conversational format.
        Each row = one log → one tactic label.
        """
        print(f"[Single-Alert] Loading dataset from {tsv_filepath}...")
        df = pd.read_csv(tsv_filepath, sep='\t')
        
        formatted_data = {"prompt": [], "completion": []}
        
        for _, row in df.iterrows():
            prompt_msg = [{"role": "user", "content": (
                f"Analyze this SIEM log and extract the exact MITRE tactic:\n{row['text']}"
            )}]
            completion_msg = [{"role": "assistant", "content": str(row['label'])}]
            
            formatted_data["prompt"].append(prompt_msg)
            formatted_data["completion"].append(completion_msg)
        
        hf_dataset = Dataset.from_dict(formatted_data)
        print(f"✅ Single-alert dataset: {len(hf_dataset)} logs formatted for training.")
        return hf_dataset

    # ---------------------------------------------------------
    # MODE 2: Campaign Pathfinding Dataset (new)
    # ---------------------------------------------------------
    def prepare_campaign_dataset(self, tsv_filepath: str) -> Dataset:
        """
        Converts the Campaign Sequences TSV into TRL conversational format.
        Each row = one ordered alert sequence → one tactic path.
        
        The model learns to read a sequence of logs and output the full
        kill chain path — not just classify one alert in isolation.
        """
        print(f"[Campaign] Loading dataset from {tsv_filepath}...")
        df = pd.read_csv(tsv_filepath, sep='\t')
        
        formatted_data = {"prompt": [], "completion": []}
        skipped = 0
        
        for _, row in df.iterrows():
            try:
                # Parse the JSON strings back into Python lists
                alert_sequence = json.loads(row['alert_sequence'])
                tactic_path = json.loads(row['tactic_path'])
                
                if not alert_sequence or not tactic_path:
                    skipped += 1
                    continue
                
                # Format the alert sequence as a numbered list for the model
                numbered_alerts = "\n".join([
                    f"[Alert {i+1}] {alert}"
                    for i, alert in enumerate(alert_sequence)
                ])
                
                # Format the tactic path as a readable arrow chain
                # e.g. "Initial Access → Privilege Escalation → Lateral Movement"
                tactic_chain = " → ".join(tactic_path)
                
                prompt_msg = [{"role": "user", "content": (
                    f"You are a SOC analyst investigating an attack campaign.\n"
                    f"Analyze the following sequence of SIEM alerts in chronological order "
                    f"and identify the complete MITRE ATT&CK kill chain path.\n\n"
                    f"Alert Sequence:\n{numbered_alerts}\n\n"
                    f"Output the ordered list of MITRE tactics this attacker followed, "
                    f"from initial compromise to final objective."
                )}]
                
                completion_msg = [{"role": "assistant", "content": tactic_chain}]
                
                formatted_data["prompt"].append(prompt_msg)
                formatted_data["completion"].append(completion_msg)
                
            except (json.JSONDecodeError, KeyError) as e:
                print(f"   [!] Skipping malformed row: {e}")
                skipped += 1
                continue
        
        hf_dataset = Dataset.from_dict(formatted_data)
        print(f"✅ Campaign dataset: {len(hf_dataset)} campaigns formatted | {skipped} skipped.")
        return hf_dataset

    # ---------------------------------------------------------
    # Shared LoRA Config builder
    # ---------------------------------------------------------
    def _build_lora_config(self) -> LoraConfig:
        return LoraConfig(
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=['gate_proj', 'down_proj', 'v_proj', 'k_proj', 'q_proj', 'o_proj', 'up_proj']
        )

    def _load_model_and_tokenizer(self):
        print(f"Initializing base model: {self.model_id}...")
        tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype=torch.bfloat16,
            device_map="auto"
        )
        return model, tokenizer

    # ---------------------------------------------------------
    # MODE 1: Train Single-Alert Adapter (existing)
    # ---------------------------------------------------------
    def train_adapter(self, dataset: Dataset):
        """Executes LoRA SFT for single-alert MITRE classification."""
        model, tokenizer = self._load_model_and_tokenizer()

        training_args = SFTConfig(
            output_dir=self.output_dir_single,
            max_seq_length=2048,
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            learning_rate=2e-4,
            logging_steps=10,
            num_train_epochs=3,
            bf16=True,
            packing=False,
            completion_only_loss=True
        )

        trainer = SFTTrainer(
            model=model,
            train_dataset=dataset,
            args=training_args,
            peft_config=self._build_lora_config(),
            processing_class=tokenizer
        )

        print("🔥 [Single-Alert] Starting SFT Training Loop...")
        trainer.train()
        trainer.save_model(self.output_dir_single)
        print(f"✅ Single-alert adapter saved to {self.output_dir_single}")

    # ---------------------------------------------------------
    # MODE 2: Train Campaign Pathfinder Adapter (new)
    # ---------------------------------------------------------
    def train_campaign_adapter(self, dataset: Dataset):
        """
        Executes LoRA SFT for campaign-level kill chain pathfinding.
        Uses a longer max_seq_length because the input is a full alert
        sequence, not a single log.
        """
        model, tokenizer = self._load_model_and_tokenizer()

        training_args = SFTConfig(
            output_dir=self.output_dir_campaign,
            max_seq_length=4096,            # Longer — needs to read full alert sequences
            per_device_train_batch_size=2,  # Smaller batch — sequences are longer
            gradient_accumulation_steps=8,  # Compensate for smaller batch
            learning_rate=2e-4,
            logging_steps=10,
            num_train_epochs=3,
            bf16=True,
            packing=False,
            completion_only_loss=True       # Only learn the tactic path output
        )

        trainer = SFTTrainer(
            model=model,
            train_dataset=dataset,
            args=training_args,
            peft_config=self._build_lora_config(),
            processing_class=tokenizer
        )

        print("🔥 [Campaign] Starting Campaign Pathfinder Training Loop...")
        trainer.train()
        trainer.save_model(self.output_dir_campaign)
        print(f"✅ Campaign pathfinder adapter saved to {self.output_dir_campaign}")


# ---------------------------------------------------------
# Local Execution Block
# ---------------------------------------------------------
if __name__ == "__main__":
    import sys
    
    forge = CommonsForge()
    
    # --- Mode 1: Single-Alert ---
    single_files = sorted(glob.glob("data/*_cartography.tsv"), key=os.path.getmtime)
    if single_files:
        latest_single = single_files[-1]
        print(f"[Single-Alert] Found training data: {latest_single}")
        single_data = forge.prepare_dataset(latest_single)
        # forge.train_adapter(single_data)
        print("[NOTE] Single-alert adapter training is commented out to save GPU state.")
    else:
        print("[!] No cartography TSV files found. Run main.py + cartography_bridge.py first.")
    
    print()
    
    # --- Mode 2: Campaign Pathfinder ---
    campaign_files = sorted(glob.glob("data/*_sequences.tsv"), key=os.path.getmtime)
    if campaign_files:
        latest_campaign = campaign_files[-1]
        print(f"[Campaign] Found training data: {latest_campaign}")
        campaign_data = forge.prepare_campaign_dataset(latest_campaign)
        # forge.train_campaign_adapter(campaign_data)
        print("[NOTE] Campaign adapter training is commented out to save GPU state.")
    else:
        print("[!] No campaign sequence TSV files found. Run campaign_bridge.py first.")