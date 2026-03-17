import os
import json
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from groq import Groq

load_dotenv()


class TaxonomyNode(BaseModel):
    category: str = Field(..., description="The broad category, e.g., 'Persistence'")
    technique: str = Field(..., description="The specific method, e.g., 'Registry Run Keys'")
    target_asset: str = Field(..., description="What is being modified, e.g., 'HKCU\\Software\\Microsoft...'")
    description: str = Field(..., description="Technical explanation of the action")

class TaxonomyTree(BaseModel):
    nodes: list[TaxonomyNode] = Field(..., description="A list of specific taxonomy nodes")


class CommonsTaxonomyEngine:
    def __init__(self):
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))
        self.model_name = "llama-3.3-70b-versatile"

    def generate_branches(self, prime_factor: str, depth: int) -> list[TaxonomyNode]:
        prompt = self._build_glan_prompt(prime_factor, depth)

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a master cybersecurity architect. "
                        "You MUST respond with valid JSON only — no preamble, no markdown fences, no explanation. "
                        "Your response must be a JSON object with a single key 'nodes' containing an array of objects. "
                        "Each object must have exactly these keys: category, technique, target_asset, description."
                    )
                },
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            response_format={"type": "json_object"},
        )

        raw = response.choices[0].message.content
        parsed_tree = TaxonomyTree.model_validate_json(raw)
        return parsed_tree.nodes

    def _build_glan_prompt(self, prime_factor: str, depth: int) -> str:
        return (
            f'Perform semantic expansion on the following root concept: "{prime_factor}". '
            f"Generate exactly {depth} highly distinct, granular, and technically accurate sub-branches (techniques and targets) "
            f"that an advanced persistent threat (APT) might use to achieve this goal. "
            f"Ensure the targets include specific registry keys, exact file paths, or network protocols where applicable."
        )


# ---------------------------------------------------------
# Local Test Block
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Testing CommonsTaxonomyEngine (Groq)...")
    try:
        engine = CommonsTaxonomyEngine()
        results = engine.generate_branches(prime_factor="Lateral Movement via Valid Accounts", depth=3)

        for i, node in enumerate(results):
            print(f"\n--- Branch {i+1} ---")
            print(f"Technique: {node.technique}")
            print(f"Target: {node.target_asset}")
            print(f"Description: {node.description}")

    except Exception as e:
        print(f"\nOops! An error occurred: {e}")