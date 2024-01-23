from urllib.parse import urlparse

# Define good TLDs to check
good_tlds = ["com", "org", "net", "edu", "gov", "co", "uk", "eu", "ca", "de", "br", "jp"]

# Checks if there is a non-standard TLD in the standard location
def bad_tld(url):
    """Checks if there is a non-standard TLD in the standard location. List of TLDs considered to be reputable:\n
    "com", "org", "net", "edu", "gov", "co", "uk", "eu", "ca", "de", "br", "jp"
    
    Args:
        url (string): The URL to be analyzed.

    Returns:
        result (boolean): True (non-standard TLD found) or False (standard TLD).
    """
    # Ensure urlparse is able to work properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    # Get domain name (i.e. netloc; exclude scheme, path, and other parts of URL)
    domain = urlparse(url).netloc
    
    # Check last split in netloc 
    split_netloc = domain.split(".")
    last_index = len(split_netloc) - 1
    if split_netloc[last_index] in good_tlds:
        # print("Standard TLD found:", split_netloc[last_index], "in", split_netloc)
        return False
    else:
        # print("Non-standard TLD found:", split_netloc[last_index], "in", split_netloc)
        return True