import tldextract

# Calculates ratio of the length of the subdomain to length of the netloc (domain + subdomain; excludes scheme)
def get_subdomain_len_ratio(url):
    """Calculates ratio of the length of the subdomain to length of the netloc (domain + subdomain; excludes scheme)

    Args:
        url (string): The URL to be analyzed. Inclusion of URL scheme is not taken into account.

    Returns:
        ratio (float): Length of the subdomain divided by the length of the netloc (domain + subdomain).
    """
    extracted = tldextract.extract(url)
    
    subdomain = extracted.subdomain
    if extracted.subdomain == '':
        netloc = extracted.domain + '.' + extracted.suffix
    else:
        netloc = extracted.subdomain + '.' + extracted.domain + '.' + extracted.suffix
    
    ratio = len(subdomain) / len(netloc)
    
    return ratio