from urllib.parse import urlparse

# Calculates the number of characters in the URL's path components.
def get_pathcomp_len(url):
    """Calculates the number of characters in the URL's path components.

    Args:
        url (string): The URL to be analyzed.

    Returns:
        length (int): Number of characters in the URL's path components.
    """
    
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    parsed = urlparse(url)
    pathcomp = parsed.path
    if parsed.params: # params are rarely used
        pathcomp += ';' + parsed.params
    if parsed.query:
        pathcomp += '?' + parsed.query
    if parsed.fragment:
        pathcomp += '#' + parsed.fragment
    
    length = len(pathcomp)
    
    return length