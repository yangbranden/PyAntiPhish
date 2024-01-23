from urllib.parse import urlparse

# Calculates the number of characters in the URL, excluding the scheme (e.g. https://)
def get_url_len(url):
    """Calculates the number of characters in the URL, excluding the scheme (e.g. https://).

    Args:
        url (string): The URL to be analyzed. Inclusion of URL scheme is not taken into account.

    Returns:
        url_len (int): Number of characters in the URL, not counting the scheme.
    """
    
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    # We do NOT include the scheme when considering length (too inconsistent)
    parsed_url = urlparse(url)
    result = parsed_url.netloc + parsed_url.path
    if parsed_url.params: # params are rarely used
        result += ';' + parsed_url.params
    if parsed_url.query:
        result += '?' + parsed_url.query
    if parsed_url.fragment:
        result += '#' + parsed_url.fragment
    
    url_len = len(result)
    
    return url_len