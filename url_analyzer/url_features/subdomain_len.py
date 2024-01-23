import tldextract

# Calculates the number of characters in the URL's subdomain.
def get_subdomain_len(url):
    """Calculates the number of characters in the URL's subdomain.

    Args:
        url (string): The URL to be analyzed. Inclusion of URL scheme is not taken into account.

    Returns:
        length (int): Number of characters in the URL's path components.
    """
    extracted = tldextract.extract(url)
    
    subdomain = extracted.subdomain
    
    length = len(subdomain)
    
    return length