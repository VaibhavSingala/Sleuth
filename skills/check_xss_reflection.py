from typing import Optional
import os

def check_xss_reflection(url: str, payload: str) -> dict:
    """
    Tests a given URL for reflected Cross-Site Scripting (XSS) by injecting 
    a specified payload into the root path and reporting execution/reflection status.

    Args:
        url: The target website URL (e.g., "http://example.com").
        payload: The XSS payload to inject (e.g., "<script>alert('XSS')</script>").

    Returns:
        A dictionary containing the results from the xss_payload_injection tool call.
    """
    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in ("1", "true", "yes", "on"):
        return {"ok": False, "error": "Skill 'check_xss_reflection' is disabled. Set SLEUTH_ALLOW_ACTIVE_SKILLS=true in .env for authorised targets only."}
    try:
        # Call the existing tool with the provided arguments
        result = ws.xss_payload_injection(url=url, payload=payload)
        return result
    except Exception as e:
        return {"error": str(e), "message": f"An error occurred while calling xss_payload_injection."}

# Example usage (optional, but good for testing):
if __name__ == '__main__':
    test_url = "https://example.com"
    test_payload = "<script>alert('XSS')</script>"
    print(f"--- Testing XSS Reflection on {test_url} with payload: {test_payload} ---")
    result = check_xss_reflection(test_url, test_payload)
    import json
    print(json.dumps(result, indent=4))