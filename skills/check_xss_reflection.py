from typing import Optional
# Assuming xss_payload_injection is available in the global scope (ws)

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
    try:
        # Call the existing tool with the provided arguments
        result = ws.xss_payload_injection(url=url, payload=payload)
        return result
    except Exception as e:
        return {"error": str(e), "message": f"An error occurred while calling xss_payload_injection."}

# Example usage (optional, but good for testing):
if __name__ == '__main__':
    test_url = "http://xpanle.xyz/"
    test_payload = "<script>alert('XSS')</script>"
    print(f"--- Testing XSS Reflection on {test_url} with payload: {test_payload} ---")
    result = check_xss_reflection(test_url, test_payload)
    import json
    print(json.dumps(result, indent=4))