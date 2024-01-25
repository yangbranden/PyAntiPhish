import tldextract
from fuzzywuzzy import fuzz

# Define whitelisted URLs/domains: https://blog.cloudflare.com/50-most-impersonated-brands-protect-phishing/
good_urls = [
    "https://www.att.com/", 
    "https://www.paypal.com/", 
    "https://www.microsoft.com/",
    "https://www.dhl.com/",
    "https://www.facebook.com/",
    "https://www.irs.gov/",
    "https://www.verizon.com/",
    "https://www.mitsubishi.com/",
    "https://www.tr.mufg.jp/",
    "https://www.mufg.jp/",
    "https://www.adobe.com/",
    "https://www.amazon.com/",
    "https://www.apple.com/",
    "https://www.wellsfargo.com/",
    "https://www.ebay.com/",
    "https://www.post.ch/",
    "https://www.naver.com/",
    "https://www.instagram.com/",
    "https://www.whatsapp.com/",
    "https://www.rakuten.com/",
    "https://www.jreast.co.jp/",
    "https://www.americanexpress.com/",
    "https://www.kddi.com/",
    "https://www.office.com/",
    "https://outlook.office365.com/",
    "https://login.microsoftonline.com/",
    "https://www.chase.com/",
    "https://aeon.co/",
    "https://www.singtel.com/",
    "https://www.optus.com.au/",
    "https://www.coinbase.com/",
    "https://banco.bradesco/",
    "https://www.caixa.gov.br/"
    "https://www.global.jcb/",
    "https://www.ing.com/",
    "https://www.hsbc.com/",
    "https://www.netflix.com/",
    "https://www.smbcgroup.com/",
    "https://nubank.com/",
    "https://nubank.com.br/",
    "https://www.bankmillennium.pl/",
    "https://www.npa.go.jp/",
    "https://allegro.pl/",
    "https://inpost.pl/",
    "https://www.correos.es/",
    "https://www.fedex.com/",
    "https://www.linkedin.com/",
    "https://www.usps.com/",
    "https://www.ups.com/",
    "https://www.google.com/",
    "https://www.google.co.uk/",
    "https://www.youtube.com/"
    "https://www.bankofamerica.com/",
    "https://www.dpd.com/",
    "https://www.itau.com.br/",
    "https://store.steampowered.com/",
    "https://steamcommunity.com/",
    "https://discord.com/",
    "https://www.swisscom.ch/",
    "https://www.lexisnexis.com/",
    "https://www.orange.com/",
    "https://www.roblox.com/",
    "https://www.homedepot.com/",
    "https://www.costco.com/",
]

# Checks if the URL is an attempt at typosquatting; utilizes the Levenshtein distance algorithm between the domain and a list of top phished brands from CloudFlare 
def is_typosquatting(url):
    """Checks if the URL is an attempt at typosquatting; utilizes the Levenshtein distance algorithm between the domain and a list of top phished brands from CloudFlare.
    (see https://blog.cloudflare.com/50-most-impersonated-brands-protect-phishing/)\n
    Considered to be typosquatting if the Levenshtein distance of the domain name results in 85% similarity or more (but not 100%).

    Args:
        url (string): The URL to be analyzed.

    Returns:
        result (boolean): True (likely a typosquatting attempt) or False (likely not typosquatting attempt).
    """
    # Ensure urlparse is able to work properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url

    # Get domain name (exclude scheme, path, and other parts of URL)
    domain = tldextract.extract(url).domain
    
    # Compare domain with whitelisted domains
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