from urllib.parse import urlparse

# HTTPS/TLS status
def tls_status(url):
    """TLS status (whether or not URL has https://)

    Args:
        url (string): The URL to be analyzed.

    Returns:
        result (boolean): True (has TLS) or False (no TLS).
    """
    # Parse the URL
    parsed_url = urlparse(url)

    # Check if the scheme is "https"
    return parsed_url.scheme == "https"