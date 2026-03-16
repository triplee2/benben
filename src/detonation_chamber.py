import json
import requests
import urllib3

# Suppress insecure HTTPS warnings since our local sandbox uses self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DetonationChamber:
    def __init__(self, api_url="https://localhost:55000", user="wazuh", password="wazuh"):
        self.api_url = api_url
        self.user = user
        self.password = password
        self.token = self._authenticate()

    def _authenticate(self) -> str:
        """Authenticates with the Wazuh API and retrieves the secure JWT."""
        print(f"Connecting to Wazuh Sandbox at {self.api_url}...")
        auth_url = f"{self.api_url}/security/user/authenticate"
        try:
            # Wazuh API requires basic auth to generate the JWT Bearer token
            response = requests.post(auth_url, auth=(self.user, self.password), verify=False, timeout=10)
            response.raise_for_status()
            
            token = response.json().get("data", {}).get("token")
            if not token:
                raise ValueError("Authentication succeeded, but no token was returned.")
            
            print("✅ Secure connection established. Sandbox is armed.")
            return token
        except requests.exceptions.RequestException as e:
            print(f"[!] Failed to connect to Wazuh API. Is the Docker container running? Error: {e}")
            return None

    def validate_log(self, synthetic_log: str, log_format: str = "syslog") -> bool:
        """
        Injects the synthetic log into the Wazuh logtest engine.
        Returns True if structurally valid, False if it is an LLM hallucination.
        """
        if not self.token:
            print("[!] Cannot detonate: Sandbox is disconnected.")
            return False

        logtest_url = f"{self.api_url}/logtest"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "event": synthetic_log,
            "log_format": log_format,
            "location": "detonation_chamber"
        }

        try:
            response = requests.put(logtest_url, headers=headers, json=payload, verify=False, timeout=5)
            response.raise_for_status()
            
            output = response.json().get("data", {}).get("output", {})
            messages = response.json().get("data", {}).get("messages", [])
            
            # Condition 1: If the engine explicitly fails to find a decoder, the log structure is broken.
            messages_str = str(messages)
            if "No decoder matched" in messages_str:
                print("❌ Validation Failed: Structural Hallucination (No Decoder Matched).")
                return False
                
            # Condition 2: If the log parses successfully and triggers a rule, it is physically viable.
            if "rule" in output:
                rule_id = output["rule"].get("id")
                print(f"✅ Validation Passed: Log structurally sound. (Triggered Sandbox Rule: {rule_id})")
                return True
                
            print("⚠️ Validation Inconclusive: Log decoded but triggered no rules.")
            return False

        except requests.exceptions.RequestException as e:
            print(f"[!] Detonation API call failed: {e}")
            return False

# ---------------------------------------------------------
# Local Execution Block for Testing
# ---------------------------------------------------------
if __name__ == "__main__":
    chamber = DetonationChamber()
    
    if chamber.token:
        print("\n--- Testing Valid Log ---")
        valid_log = "Oct 15 21:07:00 linux-agent sshd[29205]: Invalid user blimey from 18.18.18.18 port 48928"
        chamber.validate_log(valid_log)
        
        print("\n--- Testing Hallucinated/Broken Log ---")
        broken_log = "<Event><System><RandomLLMTag>This is fake</RandomLLMTag></System></Event>"
        chamber.validate_log(broken_log)