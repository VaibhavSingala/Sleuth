def check_common_vectors(url: str) -> dict:
    """
    Tests a given URL against several common web application vulnerabilities, 
    including SQL Injection (basic), Cross-Site Scripting (XSS - basic reflected), 
    and Directory Traversal.

    Args:
        url: The base URL to test (e.g., "http://example.com/").

    Returns:
        A dictionary containing the results of each test.
    """
    import os
    import requests

    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in ("1", "true", "yes", "on"):
        return {"ok": False, "error": "Skill 'check_common_vectors' is disabled. Set SLEUTH_ALLOW_ACTIVE_SKILLS=true in .env for authorised targets only."}

    results = {}
    base_url = url.rstrip('/')
    
    # --- 1. Basic SQL Injection Test (on homepage) ---
    sqli_test_url = f"{base_url}?id=1' OR 1=1 --"
    try:
        response = requests.get(sqli_test_url, timeout=10)
        # Simple heuristic: Check for common SQL keywords in the response body
        if "sqlmap" in response.text or "' OR 1=1" in response.text or "admin" in response.text.lower():
            results['SQL Injection'] = {'status': 'VULNERABLE', 'details': f"Found indicators on {sqli_test_url}"}
        else:
            results['SQL Injection'] = {'status': 'SAFE (Heuristic)', 'details': f"No immediate SQLi indicators found on {sqli_test_url}"}
    except requests.exceptions.RequestException as e:
        results['SQL Injection'] = {'status': 'ERROR', 'details': str(e)}

    # --- 2. Basic Reflected XSS Test (on homepage) ---
    xss_payload = "<script>alert('XSS_TEST')</script>"
    xss_test_url = f"{base_url}?q={requests.utils.quote(xss_payload)}"
    try:
        response = requests.get(xss_test_url, timeout=10)
        # Simple heuristic: Check if the payload string is present in the response body
        if xss_payload in response.text:
            results['Reflected XSS'] = {'status': 'VULNERABLE', 'details': f"Payload found reflected on {xss_test_url}"}
        else:
            results['Reflected XSS'] = {'status': 'SAFE (Heuristic)', 'details': f"Payload not directly reflected on {xss_test_url}"}
    except requests.exceptions.RequestException as e:
        results['Reflected XSS'] = {'status': 'ERROR', 'details': str(e)}

    # --- 3. Directory Traversal Test (on homepage) ---
    dt_test_url = f"{base_url}/../../../../etc/passwd" # Common Linux path
    try:
        response = requests.get(dt_test_url, timeout=10)
        # Simple heuristic: Check if the content looks like /etc/passwd (contains 'root:')
        if "root:" in response.text and "bin/bash" in response.text:
            results['Directory Traversal'] = {'status': 'VULNERABLE', 'details': f"Successfully accessed system file on {dt_test_url}"}
        else:
            results['Directory Traversal'] = {'status': 'SAFE (Heuristic)', 'details': f"Did not retrieve standard /etc/passwd content from {dt_test_url}"}
    except requests.exceptions.RequestException as e:
        results['Directory Traversal'] = {'status': 'ERROR', 'details': str(e)}

    return results