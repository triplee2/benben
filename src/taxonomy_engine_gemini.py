import os
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# Load the secret API key from the .env file
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
        self.client = genai.Client()
        # Using the exact flash model verified by our diagnostic script
        self.model_name = "gemini-2.0-flash" 

    def generate_branches(self, prime_factor: str, depth: int) -> list[TaxonomyNode]:
        prompt = self._build_glan_prompt(prime_factor, depth)
        
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=TaxonomyTree,
                temperature=0.7 
            )
        )
        
        parsed_tree = TaxonomyTree.model_validate_json(response.text)
        return parsed_tree.nodes

    def _build_glan_prompt(self, prime_factor: str, depth: int) -> str:
        return f"""
        You are a master cybersecurity architect building a taxonomy of post-exploitation attacker behavior.
        Your task is to perform semantic expansion on the following root concept: "{prime_factor}".
        
        Generate exactly {depth} highly distinct, granular, and technically accurate sub-branches (techniques and targets) 
        that an advanced persistent threat (APT) might use to achieve this goal.
        
        Ensure the targets include specific registry keys, exact file paths, or network protocols where applicable.
        """

if __name__ == "__main__":
    print("Testing CommonsTaxonomyEngine...")
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