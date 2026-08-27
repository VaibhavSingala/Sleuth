import os
import requests

def xss_payload_injection(url: str, payload: str) -> dict:
    """Specifically injects a given XSS payload into the root path and reports if it executes or is reflected."""
    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in ("1", "true", "yes", "on"):
        return {"ok": False, "error": "Skill 'xss_payload_injection' is disabled. Set SLEUTH_ALLOW_ACTIVE_SKILLS=true in .env for authorised targets only."}
    # Injecting into the query parameter 'q' as a common test vector. Adjust if needed.
    test_url = f"{url}?q={payload}"
    try:
        response = requests.get(test_url)
        content = response.text
        
        # Check for reflection (the payload string appearing in the HTML source)
        if payload in content:
            return {"status": "Reflected", "message": f"Payload '{payload}' was found reflected in the page source."}

        # A more advanced check would be to see if an alert() call is present, 
        # but for simplicity, we'll assume reflection means success unless proven otherwise.
        return {"status": "Not Reflected", "message": f"Payload '{payload}' was not found reflected in the page source."}

    except requests.exceptions.RequestException as e:
        return {"status": "Error", "message": f"An error occurred during the request: {e}"}