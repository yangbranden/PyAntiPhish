from urllib.parse import urlparse

# Calculates the number of characters in the URL's netloc.
def get_netloc_len(url):
    """Calculates the number of characters in the URL's netloc.

    Args:
        url (string): The URL to be analyzed.

    Returns:
        length (int): Number of characters in the URL's netloc.
    """
    
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    # We do NOT include the scheme when considering length (too inconsistent)
    parsed_url = urlparse(url)
    result = parsed_url.netloc
    
    length = len(result)
    
    return length