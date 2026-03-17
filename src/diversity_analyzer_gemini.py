import os
import numpy as np
from dotenv import load_dotenv
from google import genai

# Load secret API key
load_dotenv()

class CommonsDiversityAnalyzer:
    def __init__(self):
        self.client = genai.Client()
        # Using the specific embedding model from your unlocked list
        self.model_name = "models/gemini-embedding-2-preview"

    def get_embedding(self, text: str) -> list[float]:
        """Converts a string of text into a mathematical vector array."""
        response = self.client.models.embed_content(
            model=self.model_name,
            contents=text
        )
        # Extract the list of floats from the API response
        return response.embeddings[0].values

    def calculate_similarity(self, vec1: list[float], vec2: list[float]) -> float:
        """Calculates the cosine similarity between two vectors (0.0 to 1.0)."""
        a = np.array(vec1)
        b = np.array(vec2)
        
        dot_product = np.dot(a, b)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        
        # Prevent division by zero
        if norm_a == 0 or norm_b == 0:
            return 0.0
            
        return float(dot_product / (norm_a * norm_b))

# ---------------------------------------------------------
# Local Test Block (Test-First Methodology)
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Testing CommonsDiversityAnalyzer...\n")
    try:
        analyzer = CommonsDiversityAnalyzer()
        
        # Scenario 1: Two logs that are conceptually identical
        log_a = "The attacker used aws cli to download sensitive data from the S3 bucket."
        log_b = "AWS S3 bucket exfiltration achieved via command line interface."
        
        # Scenario 2: A log that is entirely different
        log_c = "Local administrator password reset using the net user command."
        
        print("=> Fetching embeddings from Google (this takes a second)...")
        vec_a = analyzer.get_embedding(log_a)
        vec_b = analyzer.get_embedding(log_b)
        vec_c = analyzer.get_embedding(log_c)
        
        print("\n=> Calculating Mathematical Similarity (0.0 to 1.0)...")
        sim_ab = analyzer.calculate_similarity(vec_a, vec_b)
        sim_ac = analyzer.calculate_similarity(vec_a, vec_c)
        
        print(f"Similarity (Log A vs Log B) [Should be HIGH]: {sim_ab:.4f}")
        print(f"Similarity (Log A vs Log C) [Should be LOW]:  {sim_ac:.4f}")
        
    except Exception as e:
        print(f"\nOops! An error occurred: {e}")