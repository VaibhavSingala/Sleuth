from typing import Dict, Any
# Assuming 'compare_sites' is available in the global scope (ws)

def compare_tech_stack(url_a: str, url_b: str) -> Dict[str, Any]:
    """
    Compares the technology stack, infrastructure, and keywords of two websites.

    Args:
        url_a: The first website URL to compare.
        url_b: The second website URL to compare against.

    Returns:
        A dictionary containing the comparison report from the compare_sites tool.
    """
    try:
        # Using 'standard' detail for a comprehensive yet concise report
        report = compare_sites(url_a=url_a, url_b=url_b, detail="standard")
        return report
    except Exception as e:
        return {"error": f"An error occurred while comparing sites: {e}"}

# Example usage (optional, but good for testing):
# if __name__ == '__main__':
#     result = compare_tech_stack("http://google.com", "https://www.microsoft.com")
#     print(result)