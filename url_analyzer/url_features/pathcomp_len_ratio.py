from urllib.parse import urlparse

# Calculates ratio of the length of the path components to the length of the URL (domain + subdomain; excludes scheme)
def get_pathcomp_len_ratio(url):
    """Calculates ratio of the length of the path components to the length of the URL (domain + subdomain; excludes scheme)

    Args:
        url (string): The URL to be analyzed. Inclusion of URL scheme is not taken into account.

    Returns:
        ratio (float): Length of the path components divided by the length of the netloc (domain + subdomain).
    """
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
    
    total = parsed.netloc + pathcomp
    
    ratio = len(pathcomp) / len(total)
    
    return ratio