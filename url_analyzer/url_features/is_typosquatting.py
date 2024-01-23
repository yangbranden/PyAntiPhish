import tldextract
from fuzzywuzzy import fuzz

# Define whitelisted URLs/domains
good_urls = [
    "https://www.att.com/", 
    "https://www.paypal.com/", 
    "https://www.microsoft.com/",
    "https://www.dhl.com/",
    "https://www.facebook.com/",
    "https://www.irs.gov/",
    "https://www.verizon.com/",
    "https://www.mitsubishi.com/",
    "https://www.adobe.com/",
    "https://www.amazon.com/",
    "https://www.apple.com/",
    "https://www.costco.com/",
    "https://www.wellsfargo.com/",
    "https://www.ebay.com/",
    "https://www.post.ch/",
    "https://www.naver.com/",
    "https://www.instagram.com/",
    "https://www.whatsapp.com/",
    "https://www.rakuten.com/"
    "https://www.americanexpress.com/",
    "https://www.office.com/",
    "https://outlook.office365.com/",
    "https://login.microsoftonline.com/",
    "https://www.chase.com/",
    "https://www.coinbase.com/",
    "https://www.netflix.com/",
    "https://www.fedex.com/",
    "https://www.usps.com/",
    "https://www.ups.com/",
    "https://www.linkedin.com/",
    "https://www.google.com/",
    "https://www.google.co.uk/",
    "https://www.bankofamerica.com/",
    "https://store.steampowered.com/",
    "https://steamcommunity.com/",
    "https://discord.com/",
    "https://www.roblox.com/",
    "https://www.homedepot.com/",
    "https://www.youtube.com/"
]

# Checks if the URL is an attempt at typosquatting; utilizes the Levenshtein distance algorithm between the netloc and a list of top phished brands from CloudFlare 
def is_typosquatting(url):
    """Checks if the URL is an attempt at typosquatting; utilizes the Levenshtein distance algorithm between the netloc and a list of top phished brands from CloudFlare.
    (see https://blog.cloudflare.com/50-most-impersonated-brands-protect-phishing/)\n
    Considered to be typosquatting if the Levenshtein distance results in 85% similarity or more (but not 100%).

    Args:
        url (string): The URL to be analyzed.

    Returns:
        result (boolean): True (likely a typosquatting attempt) or False (likely not typosquatting attempt).
    """
    # Ensure urlparse is able to work properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url

    # Get domain name (i.e. netloc; exclude scheme, path, and other parts of URL)
    domain = tldextract.extract(url).domain
    
    # Compare netloc with whitelisted domains' netlocs
    highest_similarity = 0
    for good_url in good_urls:
        wl_domain = tldextract.extract(good_url).domain
        similarity = fuzz.ratio(domain, wl_domain)
        # print(f"{domain} and {wl_domain} similarity: {similarity}")
        
        if similarity > highest_similarity:
            highest_similarity = similarity
    
    # Consider typosquatting if > 85% and not 100%
    if highest_similarity > 85 and highest_similarity != 100:
        return True
    
    return False