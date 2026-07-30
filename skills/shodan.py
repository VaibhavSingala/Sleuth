import requests

def shodan(query: str, max_results: int = 10) -> dict:
    """
    Searches the Shodan database for hosts matching a given query string.

    Args:
        query (str): The search term (e.g., "nginx http" or an IP address).
        max_results (int, optional): The maximum number of results to return. Defaults to 10.

    Returns:
        dict: A dictionary containing the JSON response from the Shodan API.
              Returns an error message if the request fails.
    """
    API_KEY = "YOUR_SHODAN_API_KEY"  # IMPORTANT: Replace this with your actual Shodan API Key
    url = f"https://api.shodan.io/shodan/search?query={requests.utils.quote(query)}&limit={max_results}"

    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred while querying Shodan: {e}"}

if __name__ == '__main__':
    # Example usage if the file is run directly
    print("--- Running example shodan search for 'apache' ---")
    results = shodan(query="apache", max_results=5)
    import json
    print(json.dumps(results, indent=2))