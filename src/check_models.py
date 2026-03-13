import os
from dotenv import load_dotenv
from google import genai

# Load your secret key
load_dotenv()

print("Querying Google AI Studio for your unlocked models...\n")

try:
    client = genai.Client()
    available_models = client.models.list()
    
    print("✅ Here are ALL the models unlocked for your API key:")
    for model in available_models:
        print(f"- {model.name}")
            
except Exception as e:
    print(f"Error fetching models: {e}")