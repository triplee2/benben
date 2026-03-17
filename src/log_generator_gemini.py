import os
import json
from dotenv import load_dotenv
from pydantic import BaseModel, Field
from typing import Optional, List
from google import genai
from google.genai import types

load_dotenv()

# 1. Strict Sub-Models (No open-ended Dicts allowed by the API!)
class MitreData(BaseModel):
    id: List[str] = Field(..., description="List of MITRE IDs, e.g., ['T1070']")
    tactic: List[str] = Field(..., description="List of MITRE tactics, e.g., ['Defense Evasion']")

class WazuhManager(BaseModel):
    name: str = Field(default="commons-wazuh-manager", description="The name of the SIEM manager")

class ExtractedData(BaseModel):
    command_line: Optional[str] = Field(None, description="Extracted command line string, if applicable")
    hashes: Optional[str] = Field(None, description="Extracted file hashes, if applicable")
    target_user: Optional[str] = Field(None, description="Targeted user account, if applicable")
    source_ip: Optional[str] = Field(None, description="Source IP address, if applicable")

class WazuhRule(BaseModel):
    id: str = Field(..., description="Wazuh rule ID (e.g., '1002', '5716', '60106')")
    level: int = Field(..., description="Alert severity level from 0 to 16")
    description: str = Field(..., description="Description of the triggered rule")
    firedtimes: int = Field(1, description="Number of times this rule fired")
    mitre: Optional[MitreData] = Field(None, description="MITRE ATT&CK mapping")

class WazuhAgent(BaseModel):
    id: str = Field(default="001", description="Agent ID")
    name: str = Field(default="WIN-TARGET-01", description="Hostname of compromised machine")
    ip: str = Field(default="192.168.1.105", description="IP address of the agent")

class WazuhDecoder(BaseModel):
    name: str = Field(..., description="Decoder used, e.g., 'sysmon', 'windows-eventchannel', 'json'")

class WazuhAlertSchema(BaseModel):
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    rule: WazuhRule
    agent: WazuhAgent
    manager: WazuhManager
    id: str = Field(..., description="Unique alert ID string")
    decoder: WazuhDecoder
    full_log: str = Field(..., description="The authentic raw application log string (e.g., raw Windows XML or Syslog)")
    data: Optional[ExtractedData] = Field(None, description="Dynamic fields extracted from the log")
    location: str = Field(..., description="File or channel, e.g., 'EventChannel' or '/var/log/auth.log'")

# 2. The Log Generator Engine
class CommonsLogGenerator:
    def __init__(self):
        self.client = genai.Client()
        self.model_name = "gemini-2.0-flash"

    def synthesize_wazuh_alert(self, action_description: str, time_offset_minutes: int) -> WazuhAlertSchema:
        """Translates a single human-readable attack step into a strict Wazuh JSON alert."""
        prompt = self._build_prompt(action_description, time_offset_minutes)
        
        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=WazuhAlertSchema,
                temperature=0.4 # Lower temperature for strict technical accuracy in logs
            )
        )
        
        return WazuhAlertSchema.model_validate_json(response.text)

    def _build_prompt(self, action_description: str, time_offset_minutes: int) -> str:
        return f"""
        You are a SIEM engine generating a strictly formatted Wazuh alerts.json entry.
        Translate the following attacker action into a highly realistic Wazuh alert:
        
        Action: "{action_description}"
        Time Offset: +{time_offset_minutes} minutes
        
        Ensure the 'full_log' contains an incredibly authentic raw string (like a Windows Sysmon Event ID 1 XML string, or a raw Linux auditd log).
        Map the 'rule.id' and 'rule.level' to realistic Wazuh security rules.
        Populate the 'data' structure with extracted fields like command lines or IPs if they exist in the action.
        """

# ---------------------------------------------------------
# Local Test Block
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Testing CommonsLogGenerator...")
    try:
        generator = CommonsLogGenerator()
        
        # We are feeding it Step 8 from your exact timeline!
        test_action = "Clear relevant event logs on the target host to remove traces of the successful logon. Specifically target the Security event log. Command: wevtutil cl Security"
        
        alert = generator.synthesize_wazuh_alert(action_description=test_action, time_offset_minutes=25)
        
        print(f"\n[ Generated Wazuh Alert ]\n")
        print(alert.model_dump_json(indent=2))
            
    except Exception as e:
        print(f"\nOops! An error occurred: {e}")