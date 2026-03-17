import os
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

load_dotenv()

# 1. Define the strict timeline schema
class AttackStep(BaseModel):
    step_number: int = Field(..., description="The chronological order of the action")
    action_description: str = Field(..., description="Highly detailed, technical description of the exact command or action taken")
    time_offset_minutes: int = Field(..., description="Minutes elapsed since the start of the attack")

class AttackTimeline(BaseModel):
    narrative: list[AttackStep] = Field(..., description="The step-by-step timeline of the attack")

# 2. Build the Expander Engine
class CommonsComplexityExpander:
    def __init__(self):
        self.client = genai.Client()
        self.model_name = "gemini-2.0-flash"

    def generate_timeline(self, technique: str, target: str) -> list[AttackStep]:
        """Expands a single taxonomy node into a multi-step attack narrative."""
        prompt = self._build_prompt(technique, target)
        
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AttackTimeline,
                temperature=0.8 # Slightly higher temperature for creative stealth tactics
            )
        )
        
        parsed_timeline = AttackTimeline.model_validate_json(response.text)
        return parsed_timeline.narrative

    def _build_prompt(self, technique: str, target: str) -> str:
        return f"""
        You are an elite Red Team operator simulating an advanced persistent threat.
        Your objective is to execute the following technique: "{technique}" against the target: "{target}".
        
        Break this single objective down into a realistic, step-by-step timeline of micro-actions. 
        Include reconnaissance, preparation, execution, and cleanup. 
        Specify exact command line tools, PowerShell scripts, or network utilities you would type.
        """

# ---------------------------------------------------------
# Local Test Block
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Testing CommonsComplexityExpander...")
    try:
        expander = CommonsComplexityExpander()
        
        # We are feeding it the exact output from your Branch 1 test!
        test_technique = "Remote Desktop Protocol (RDP) with Stolen Credentials"
        test_target = "TCP port 3389, RDP service on target host"
        
        timeline = expander.generate_timeline(technique=test_technique, target=test_target)
        
        print(f"\n[ Attack Timeline for: {test_technique} ]\n")
        for step in timeline:
            print(f"T+{step.time_offset_minutes} mins | Step {step.step_number}: {step.action_description}")
            
    except Exception as e:
        print(f"\nOops! An error occurred: {e}")