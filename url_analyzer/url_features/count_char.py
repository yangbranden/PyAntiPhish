# Counts number of characters within the URL
def count_char(url, char):
    """Counts number of specified character within the URL.

    Args:
        url (string): The URL to be analyzed.
        char (char): The character to count within the URL.

    Returns:
        count (int): Number of occurrences of char in url.
    """
    count = 0
    for c in url:
        if c == char:
            count += 1
    return count