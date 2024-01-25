from urllib.parse import urlparse

# Calculates ratio of the length of the URL's netloc (subdomain + domain) to the total length of the URL (excludes scheme).
def get_netloc_len_ratio(url):
    """Calculates ratio of the length of the URL's netloc (subdomain + domain) to the total length of the URL (excludes scheme).

    Args:
        url (string): The URL to be analyzed.

    Returns:
        ratio (float): Length of the netloc divided by the length of the URL (excludes scheme).
    """
    
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    # We do NOT include the scheme when considering length (too inconsistent)
    parsed = urlparse(url)
    
    pathcomp = parsed.path
    if parsed.params: # params are rarely used
        pathcomp += ';' + parsed.params
    if parsed.query:
        pathcomp += '?' + parsed.query
    if parsed.fragment:
        pathcomp += '#' + parsed.fragment
    
    netloc = parsed.netloc
    total = parsed.netloc + pathcomp
    
    print(total)
    ratio = len(netloc) / len(total)
    
    return ratio