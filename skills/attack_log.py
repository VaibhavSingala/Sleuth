# Global storage for attack records
ATTACK_LOG = []

def attack_log(url: str, scanner: str, findings: dict) -> bool:
    """
    Records a new attack test result into the global log and checks for duplicates.

    Args:
        url (str): The target URL that was scanned.
        scanner (str): The tool used for the scan (e.g., 'wapiti_scan', 'zap_scan').
        findings (dict): A dictionary containing the results, typically structured as 
                         {'category': [list_of_issues], ...} or a summary dict.

    Returns:
        bool: True if the attack was successfully logged, False otherwise (if it's a duplicate).
    """
    # Check for exact duplicate (URL + Scanner) before adding
    for record in ATTACK_LOG:
        if record['url'] == url and record['scanner'] == scanner:
            print(f"--- WARNING: Duplicate entry found for {url} using {scanner}. Not overwriting. ---")
            return False

    # Create the new record
    new_record = {
        'timestamp': '2026-07-26 (Current)', # In a real system, use datetime.now()
        'url': url,
        'scanner': scanner,
        'findings': findings
    }

    ATTACK_LOG.append(new_record)
    print(f"SUCCESS: Attack record added for {url} using {scanner}.")
    return True

# Helper functions (can be called internally or externally via other skills if needed)
def get_all_attacks() -> list:
    """Retrieves the entire stored attack log."""
    print("--- ATTACK LOG RETRIEVAL SUCCESSFUL ---")
    return ATTACK_LOG

def check_for_duplicate(url: str, scanner: str) -> bool:
    """Checks if a specific URL/Scanner combination already exists in the log."""
    for record in ATTACK_LOG:
        if record['url'] == url and record['scanner'] == scanner:
            return True
    print(f"--- CHECK COMPLETE: No existing log found for {url} using {scanner}. ---")
    return False