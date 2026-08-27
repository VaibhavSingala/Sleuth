import os
import requests

def brute_force_login(url: str, username: str, password: str) -> dict:
    """Attempts a login on the specified URL using provided credentials and returns success/failure."""
    if os.environ.get("SLEUTH_ALLOW_ACTIVE_SKILLS", "").strip().lower() not in ("1", "true", "yes", "on"):
        return {"ok": False, "error": "Skill 'brute_force_login' is disabled. Set SLEUTH_ALLOW_ACTIVE_SKILLS=true in .env for authorised targets only."}
    # Assuming a standard POST request to a /login endpoint. Adjust 'login' if necessary.
    login_endpoint = f"{url}/login" 
    payload = {
        "username": username,
        "password": password
    }
    try:
        response = requests.post(login_endpoint, data=payload)
        # Common ways to detect successful login: status code 200/302, or checking for a success message in the body
        if response.status_code == 200 and "Welcome" in response.text:
            return {"status": "Success", "message": f"Login successful for {username}."}
        elif response.status_code in [301, 302]: # Redirect often means success
             return {"status": "Success (Redirect)", "message": f"Login successful for {username}, redirected."}
        else:
            # Check for common failure messages
            if "Invalid credentials" in response.text or "Failed to log in" in response.text:
                return {"status": "Failure", "message": f"Login failed for {username}: Invalid credentials."}
            else:
                 return {"status": "Ambiguous", "message": f"Login attempt returned status code {response.status_code}. Check content."}

    except requests.exceptions.RequestException as e:
        return {"status": "Error", "message": f"An error occurred during the request: {e}"}