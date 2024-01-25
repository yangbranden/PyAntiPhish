import tldextract
from urllib.parse import urlparse

# Calculates ratio of the length of the subdomain to the total length of the URL (excludes scheme)
def get_subdomain_len_ratio(url):
    """Calculates ratio of the length of the subdomain to the total length of the URL (excludes scheme)

    Args:
        url (string): The URL to be analyzed. Inclusion of URL scheme is not taken into account.

    Returns:
        ratio (float): Length of the subdomain divided by the length of the URL (excludes scheme).
    """
    extracted = tldextract.extract(url)
    
    subdomain = extracted.subdomain
    
    parsed = urlparse(url)
    pathcomp = parsed.path
    if parsed.params: # params are rarely used
        pathcomp += ';' + parsed.params
    if parsed.query:
        pathcomp += '?' + parsed.query
    if parsed.fragment:
        pathcomp += '#' + parsed.fragment
    
    total = parsed.netloc + pathcomp
    
    ratio = len(subdomain) / len(total)
    
    return ratio