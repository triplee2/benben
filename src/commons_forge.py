import os
import pandas as pd
import torch
from datasets import Dataset
from peft import LoraConfig
from trl import SFTTrainer, SFTConfig
from transformers import AutoModelForCausalLM, AutoTokenizer

class CommonsForge:
    def __init__(self, model_id="Qwen/Qwen2.5-1.5B-Instruct", output_dir="models/commons-siem-detector"):
        self.model_id = model_id
        self.output_dir = output_dir
        
    def prepare_dataset(self, tsv_filepath: str) -> Dataset:
        """Converts the Cartography TSV into the TRL conversational format."""
        print(f"Loading dataset from {tsv_filepath}...")
        df = pd.read_csv(tsv_filepath, sep='\t')
        
        # Format for TRL's prompt-completion standard
        formatted_data = {
            "prompt": [],
            "completion": []
        }
        
        for _, row in df.iterrows():
            # The User asks the model to classify the raw log
            prompt_msg = [{"role": "user", "content": f"Analyze this SIEM log and extract the exact MITRE tactic:\n{row['text']}"}]
            # The Assistant replies strictly with the label from our TSV
            completion_msg = [{"role": "assistant", "content": str(row['label'])}]
            
            formatted_data["prompt"].append(prompt_msg)
            formatted_data["completion"].append(completion_msg)
            
        hf_dataset = Dataset.from_dict(formatted_data)
        print(f"✅ Successfully formatted {len(hf_dataset)} logs for training.")
        return hf_dataset

    def train_adapter(self, dataset: Dataset):
        """Executes the LoRA Supervised Fine-Tuning loop."""
        print(f"Initializing base model: {self.model_id}...")
        
        # Load Tokenizer & Base Model
        tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        model = AutoModelForCausalLM.from_pretrained(
            self.model_id, 
            torch_dtype=torch.bfloat16,
            device_map="auto"
        )

        # Full LoRA Configuration targeting all Attention & MLP layers
        peft_config = LoraConfig(
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=['gate_proj', 'down_proj', 'v_proj', 'k_proj', 'q_proj', 'o_proj', 'up_proj']
        )

        # SFT Training Arguments
        training_args = SFTConfig(
            output_dir=self.output_dir,
            max_seq_length=2048,
            per_device_train_batch_size=4,
            gradient_accumulation_steps=4,
            learning_rate=2e-4,
            logging_steps=10,
            num_train_epochs=3,
            bf16=True, # Use bfloat16 for modern GPU acceleration
            packing=False,
            completion_only_loss=True # Forces the model to only learn the MITRE labels
        )

        trainer = SFTTrainer(
            model=model,
            train_dataset=dataset,
            args=training_args,
            peft_config=peft_config,
            processing_class=tokenizer
        )

        print("🔥 Igniting the Forge: Starting SFT Training Loop...")
        trainer.train()
        
        print(f"✅ Training complete. Saving deployable LoRA adapter to {self.output_dir}...")
        trainer.save_model(self.output_dir)

# ---------------------------------------------------------
# Local Execution Block
# ---------------------------------------------------------
if __name__ == "__main__":
    import glob
    print("Initializing Commons Forge...\n")
    
    # Auto-detect the latest cartography file
    search_pattern = "data/*_cartography.tsv"
    files = glob.glob(search_pattern)
    
    if not files:
        print("[!] No cartography TSV files found in data/ directory. Run main.py first.")
    else:
        latest_tsv = max(files, key=os.path.getmtime)
        print(f"Found training data: {latest_tsv}")
        
        forge = CommonsForge()
        train_data = forge.prepare_dataset(latest_tsv)
        
        # Uncomment the line below to actually trigger the GPU training loop
        # forge.train_adapter(train_data)
        print("\n[NOTE] Adapter training is currently commented out to save GPU state.")