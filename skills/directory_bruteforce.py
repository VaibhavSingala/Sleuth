import requests
from typing import Optional

def directory_bruteforce(url: str, wordlist_path: str, timeout: int = 5) -> dict:
    """
    Performs a dictionary-based brute-force scan on the specified URL.

    It reads words from the provided wordlist file and checks each path appended to the base URL.
    A successful response (HTTP status code 200) is considered a found directory/file.

    Args:
        url: The base URL to scan (e.g., "http://example.com").
        wordlist_path: The file path to the dictionary wordlist.
        timeout: Request timeout in seconds.

    Returns:
        A dictionary containing 'found_paths' (list of successful paths) 
        and 'total_tested' (integer count).
    """
    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return {
            "error": f"Wordlist not found at path: {wordlist_path}",
            "found_paths": [],
            "total_tested": 0
        }

    base_url = url.rstrip('/')
    found_paths = []
    total_tested = 0

    print(f"[*] Starting directory brute-force on: {base_url}")
    print(f"[*] Using wordlist from: {wordlist_path}")
    print("-" * 40)

    for word in words:
        total_tested += 1
        target_url = f"{base_url}/{word}"
        try:
            # Use HEAD request as it's faster than GET, only fetching headers
            response = requests.head(target_url, timeout=timeout, allow_redirects=True)
            
            # Check for success status code (200 OK is standard, but 3xx redirects are also often valid findings)
            if response.status_code == 200:
                found_paths.append(target_url)
                print(f"[+] FOUND: {target_url} (Status: {response.status_code})")
            # Optionally, you could check for other codes like 301/302 if you want to capture redirects as "found" too
            elif response.status_code >= 300 and response.status_code < 400:
                 print(f"[~] REDIRECT: {target_url} (Status: {response.status_code})")

        except requests.exceptions.RequestException as e:
            # Handle connection errors, timeouts, DNS issues, etc.
            # print(f"[-] Error checking {word}: {e}") # Uncomment for verbose output
            pass

    print("-" * 40)
    return {
        "found_paths": found_paths,
        "total_tested": total_tested
    }

if __name__ == '__main__':
    # --- Example Usage ---
    TARGET_URL = "http://xpanle.xyz/"  # Change this to your target site
    WORDLIST_FILE = "common.txt"     # Ensure you have a wordlist named common.txt in the project root

    print(f"--- Running Directory Brute-Force Example ---")
    results = directory_bruteforce(TARGET_URL, WORDLIST_FILE)
    
    if "error" in results:
        print(f"\n[!!!] ERROR DURING SCAN:")
        print(results["error"])
    else:
        print("\n=========================================")
        print("          SCAN COMPLETE SUMMARY")
        print("=========================================")
        print(f"Total Paths Tested: {results['total_tested']}")
        print(f"Paths Found (200 OK): {len(results['found_paths'])}")
        if results['found_paths']:
            print("\n--- List of Found Paths ---")
            for path in results['found_paths'][:10]: # Print top 10 for brevity
                print(f"  -> {path}")
            if len(results['found_paths']) > 10:
                 print(f"  ... and {len(results['found_paths']) - 10} more.")
        else:
             print("No paths returned a 200 OK status code.")