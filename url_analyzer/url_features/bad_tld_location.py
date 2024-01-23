from urllib.parse import urlparse

# Define good TLDs to check
good_tlds = ["com", "org", "net", "edu", "gov", "co", "uk", "eu", "ca", "de", "br", "jp"]

# Checks if a standard TLD is found in a non-standard location (i.e. not at the end of the URL)
def bad_tld_location(url):
    """Checks if a standard TLD is found in a non-standard location (i.e. not at the end of the URL). List of TLDs considered to be reputable:\n
    "com", "org", "net", "edu", "gov", "co", "uk", "eu", "ca", "de", "br", "jp"

    Args:
        url (string): The URL to be analyzed.

    Returns:
        result (boolean): True (non-standard TLD location) or False (standard TLD location) 
    """
    # Ensure urlparse is able to work properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url

    # Get domain name (i.e. netloc; exclude scheme, path, and other parts of URL)
    domain = urlparse(url).netloc
    
    # Check if each portion of netloc is a TLD; if out of place then 
    split_netloc = domain.split(".")
    for i in range(len(split_netloc)):
        if split_netloc[i] in good_tlds and i not in [len(split_netloc) - 1, len(split_netloc) - 2]:
            # print("Non-standard TLD found:", split_netloc[i], "in", split_netloc, "at index", i)
            return True
    return False