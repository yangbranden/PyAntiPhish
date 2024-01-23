from urllib.parse import urlparse
import socket

# Checks if the URL netloc is a raw IP address
def raw_ip_as_url(url):
    """Checks if the URL netloc is a raw IP address.

    Args:
        url (string): The URL to be analyzed.

    Returns:
        result (boolean): True (has a raw IP address as the URL) or False (no raw IP address as URL). 
    """
    # Extract the netloc (network location) part from the parsed URL
    domain = urlparse(url).netloc
    
    try:
        # inet_aton gives socket error if not valid IPv4 address
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False