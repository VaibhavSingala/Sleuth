from typing import Optional

# Assuming 'read_url' is available in the scope (which it is)
def webscrape(url: str, max_chars: Optional[int] = None) -> str:
    """
    Scrapes the content of a given URL by fetching and returning its main text.

    Args:
        url: The full URL of the webpage to scrape (e.g., "http://example.com").
        max_chars: The maximum number of characters to return from the page. 
                   If None, the default limit of read_url will be used.

    Returns:
        A string containing the main text content of the scraped webpage.
    """
    return read_url(url=url, max_chars=max_chars)