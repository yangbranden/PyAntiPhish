#!/usr/bin/python3

# Features extracted from script:
#  0. All offline checks
#  1. Has <form> tag asking for PII:
#       > an <input> tag in the form
#       > attributes contain keywords in blacklist (e.g. "password", "credit card number")
#  2. Asks for username/email address
#  3. Asks for password/pin number
#  4. Asks for phone number
#  5. Asks for birthday
#  6. Asks for credit/debit card number
#  7. Asks for social security number
#  8. Malicious "action" attribute; value is among:
#       a. Empty (capable of running JS)
#       b. Domain different from the webpage domain
#  9. Ratio of nil anchors (href="#") to all anchors (i.e. percentage of nil anchors)
# 10. TF-IDF of page
# 11. Browser Lookup (again Google API client) for domain name + <title> tag content
# 12. Google Safe Browsing
# 13. VirusTotal API
# 14. PhishTank online-valid list check
# 15. WHOIS lookups

import requests
from bs4 import BeautifulSoup
import csv
import os
import socket
from urllib.parse import urlparse
import pickle
import numpy as np
import random
import tldextract
from fuzzywuzzy import fuzz

# Stuff from offline checks
########################################################################################################################################################

# Define good TLDs to check
good_tlds = ["com", "org", "net", "edu", "gov", "co", "uk", "eu", "ca", "de", "br", "jp"]

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

# Feature 1 is length of whole URL; we exclude scheme because too inconsistent
def get_url_len(url):
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    # We do NOT include the scheme when considering length (too inconsistent)
    parsed_url = urlparse(url)
    result = parsed_url.netloc + parsed_url.path
    if parsed_url.params: # params are rarely used
        result += ';' + parsed_url.params
    if parsed_url.query:
        result += '?' + parsed_url.query
    if parsed_url.fragment:
        result += '#' + parsed_url.fragment
    
    url_len = len(result)
    
    return url_len

# Feature 2 is length of the netloc of the URL (again exclude scheme)
def get_netloc_len(url):
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    netloc_len = len(urlparse(url).netloc)
    
    return netloc_len

# Feature 3 is length of path components of the URL (again exclude scheme)
def get_pathcomp_len(url):
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    parsed_url = urlparse(url)
    result = parsed_url.path
    if parsed_url.params: # params are rarely used
        result += ';' + parsed_url.params
    if parsed_url.query:
        result += '?' + parsed_url.query
    if parsed_url.fragment:
        result += '#' + parsed_url.fragment
    pathcomp_len = len(result)
    
    return pathcomp_len

# Features 4-20 (character count)
def count_char(url, char):
    count = 0
    for c in url:
        if c == char:
            count += 1
    return count

# Feature 21 (Non-standard TLD in standard location)
def bad_tld(url):
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

# Feature 22 (Standard TLD in non-standard location)
def bad_tld_location(url):
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

# Feature 23 (Raw IP as URL (netloc))
def raw_ip_as_url(url):
    # Extract the netloc (network location) part from the parsed URL
    domain = urlparse(url).netloc
    
    try:
        # inet_aton gives socket error if not valid IPv4 address
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

# Feature 24 (HTTPS/TLS status)
def tls_status(url):
    # Parse the URL
    parsed_url = urlparse(url)

    # Check if the scheme is "https"
    return parsed_url.scheme == "https"

# Feature 25 (Typosquatting; Levenshtein distance with netloc)
def is_typosquatting(url):
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

# Additional online features
#  1. Has <form> tag asking for PII:
#       > an <input> tag in the form
#       > attributes contain keywords in blacklist (e.g. "password", "credit card number")
#  2. Asks for username/email address
#  3. Asks for password/pin number
#  4. Asks for phone number
#  5. Asks for birthday
#  6. Asks for credit/debit card number
#  7. Asks for social security number
#  8. Malicious "action" attribute; value is among:
#       a. Empty (capable of running JS)
#       b. Domain different from the webpage domain
#  9. Ratio of nil anchors (href="#") to all anchors (i.e. percentage of nil anchors)
# 10. TF-IDF of page to get term set --> Browser Lookup (Google API client) of term set + *maybe* <title> tag content
# 11. Google Safe Browsing
# 12. VirusTotal API 
# 13. WHOIS lookups
# 14. Known-phishing database feeds (PhishTank, OpenPhish, Phishing.Database) - basically just make a big list in Python and check if the URL is in there
########################################################################################################################################################

blacklisted_words = [
    "login", "username", "email", "email address", "e-mail", "e-mail address", 
    "password", "passphrase", "passcode", "pin", "pin number",
    "phone number", "telephone number", "mobile number", "cell phone number",
    "birthday", "birth day", "birth date", "date of birth", "dob", "bday",
    "credit card", "credit card number", "debit card", "debit card number", "card number", "card verification", "card verification value", "cvv", "expiration date", "expiry date", "bank account number",
    "social security number", "social security", "ssn", "ssn id", "ssn digits",
    "mother's maiden name"
]

# Feature 1: Has <form> asking for PII
def bad_form(response_content):
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response_content, 'html.parser') # response.content has the HTML DOM, we use bs4 to parse it
    
    # Search through <form> content
    form_tags = soup.find_all('form')
    if len(form_tags) != 0:
        for form_tag in form_tags:
            print(form_tag)
            
            # Check if has input tag
            input_tags = form_tag.find_all('input')
            if len(input_tags) == 0:
                print("No input tags found")
                continue
            
            # Check if contains blacklisted words
            for input_tag in input_tags:
                for attribute, value in input_tag.attrs.items():
                    attr_value = str(value).lower()
                    for bl_word in blacklisted_words:
                        similarity_ratio = fuzz.ratio(bl_word, attr_value)
                        # print(f"The similarity ratio between '{bl_word}' and '{str(value)}' is: {similarity_ratio}%")
                        # Potentially malicious if it has 85% similarity or is within the string
                        if similarity_ratio > 85 or bl_word in value:
                            print(f"POTENTIALLY MALICIOUS INPUT FOUND: '{bl_word}' and '{str(value)}' SIMILARITY: {similarity_ratio}%")
                            print(f"{input_tag}\n")
                            return True
    else:
        print("No form content found")
    
    return False

# Feature 2-7: Asks for certain PII; identified by searching <form>'s <input> tags with keywords (Levenshtein distance + contains check)
def asks_for_pii(response_content, keywords):
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response_content, 'html.parser')
    
    # Search through <form> content
    form_tags = soup.find_all('form')
    if len(form_tags) != 0:
        for form_tag in form_tags:
            # Check if has input tag
            input_tags = form_tag.find_all('input')
            if len(input_tags) == 0:
                print("No input tags found")
                continue
            
            # Check if contains blacklisted words
            for input_tag in input_tags:
                for attribute, value in input_tag.attrs.items():
                    attr_value = str(value).lower()
                    for keyword in keywords:
                        similarity_ratio = fuzz.ratio(keyword, attr_value)
                        # print(f"The similarity ratio between '{keyword}' and '{str(value)}' is: {similarity_ratio}%")
                        # Potentially malicious if it has 85% similarity or is within the string
                        if similarity_ratio > 85 or keyword in value:
                            # print(f"DETECTED INPUT ASKING FOR PII ({keywords}): '{keyword}' and '{str(value)}' SIMILARITY: {similarity_ratio}%")
                            # print(f"{input_tag}\n")
                            return True
    else:
        print("No form content found")
    
    return False

# Feature 8: Malicious "action" attribute; value is among:
#       a. Empty (capable of running JS)
#       b. Domain different from the webpage domain
def bad_action(response_content, url):
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response_content, 'html.parser')
    
    # Search through <form> content for all "action" attributes
    form_tags = soup.find_all('form')
    if len(form_tags) != 0:
        for form in form_tags:
            # print(form)
            action_attribute = form.get('action')
        
            # Check if empty action
            if action_attribute is None or action_attribute == '#' or action_attribute == '':
                # print("BAD 1")
                return True
        
            # Check if redirect out of domain
            current_domain = tldextract.extract(url).domain
            action_domain = tldextract.extract(action_attribute).domain
            # print("comparing", current_domain, action_domain)
            if action_domain != current_domain:
                # print("BAD 2")
                return True
    else:
        print("No form content")

    return False

# Feature 9: Ratio of nil anchors (href="#" or href="javascript:void(0)") to all anchors (i.e. percentage of nil anchors)
def nil_anchor_ratio(html_content):
    # Parse the HTML content
    soup = BeautifulSoup(html_content, 'html.parser')

    # Find all <a> tags with href="#" or href="" or href="javascript:void(0)"
    nil_anchors = soup.find_all('a', href=['#', '', 'javascript:void(0)'])

    # Calculate the ratio
    total_anchors = len(soup.find_all('a'))
    nil_anchor_count = len(nil_anchors)

    if total_anchors == 0:
        return 0  # Avoid division by zero
    else:
        return nil_anchor_count / total_anchors

# Feature 10: TF-IDF of page


########################################################################################################################################################

# Use simple GET request for HTML DOM
def get_html_dom(url):
    # Send a GET request to the URL
    response = requests.get(url)

    # Check if the request was successful (status code 200)
    if response.status_code == 200:
        return response.content, True
    
    else:
        print("Failed to retrieve the webpage. Status code:", response.status_code)
        return None, False

# Write row of CSV
def write_to_csv(filename, url, result):
    file_exists = os.path.exists(filename)

    # Read file if exists
    if file_exists:
        with open(filename, 'r', newline='') as f:
            reader = csv.reader(f)
            
            # Only append row if url doesn't already exist
            for row in reader:
                website_url = row[0]
                if website_url == url:
                    print(f"URL {url} already found; skipping.")
                    return False
    
    # Open file as append (creates file if doesn't exist)
    with open(filename, 'a', newline='') as f:
        csv_writer = csv.writer(f)

        # Perform HTTP request, exit if no response
        response = requests.get(url)

        if not file_exists:
            # Write header row
            csv_writer.writerow([
                "website_url", "url_length", "netloc_length", "pathcomp_length", "period_count", "slash_count", "percent_count", "dash_count", "underscore_count", 
                "question_count", "ampersand_count", "hashsign_count", "exclamation_count", "atsign_count", "comma_count", "equal_count", "plus_count", 
                "colon_count", "semicolon_count", "tilde_count", "dollar_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", "has_tls", "typosquatting", 
                "has_bad_form", "asks_username_email", "asks_password", "asks_phone", "asks_birthday", "asks_card_info", "asks_ssn", "has_bad_action",
                "result"
            ])

        url_length = get_url_len(url)
        netloc_length = get_netloc_len(url)
        pathcomp_length = get_pathcomp_len(url)
        period_count = count_char(url, '.')
        slash_count = count_char(url, '/')
        percent_count = count_char(url, '%')
        dash_count = count_char(url, '-')
        underscore_count = count_char(url, '_')
        question_count = count_char(url, '?')
        ampersand_count = count_char(url, '&')
        hashsign_count = count_char(url, '#')
        exclamation_count = count_char(url, '!')
        atsign_count = count_char(url, '@')
        comma_count = count_char(url, ',')
        equal_count = count_char(url, '=')
        plus_count = count_char(url, '+')
        colon_count = count_char(url, ':')
        semicolon_count = count_char(url, ';')
        tilde_count = count_char(url, '~')
        dollar_count = count_char(url, '$')
        has_bad_tld = bad_tld(url)
        has_bad_tld_location = bad_tld_location(url)
        has_raw_ip = raw_ip_as_url(url)
        has_tls = tls_status(url)
        typosquatting = is_typosquatting(url)
        has_bad_form = bad_form(response)
        asks_username_email = asks_for_pii(response, ["login", "username", "email", "email address", "e-mail", "e-mail address"])
        asks_password = asks_for_pii(response, ["password", "passphrase", "passcode", "pin", "pin number"])
        asks_phone = asks_for_pii(response, ["phone number", "telephone number", "mobile number", "cell phone number"])
        asks_birthday = asks_for_pii(response, ["birthday", "birth day", "birth date", "date of birth", "dob", "bday"])
        asks_card_info = asks_for_pii(response, ["credit card", "credit card number", "debit card", "debit card number", "card number", "card verification", "card verification value", "cvv", "expiration date", "expiry date"])
        asks_ssn = asks_for_pii(response, ["social security number", "social security", "ssn", "ssn id", "ssn digits"])
        has_bad_action = bad_action(response, url)
        
        row = [
            url, url_length, netloc_length, pathcomp_length, period_count, slash_count, percent_count, dash_count, underscore_count, 
            question_count, ampersand_count, hashsign_count, exclamation_count, atsign_count, comma_count, equal_count, plus_count, 
            colon_count, semicolon_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, typosquatting, 
            has_bad_form, asks_username_email, asks_password, asks_phone, asks_birthday, asks_card_info, asks_ssn, has_bad_action,
            result
        ]

        csv_writer.writerow(row)
        # print("Data written to CSV file:", row)
        return True

if __name__ == "__main__":
    # website_url = input("Enter the website URL: ")
    # html_dom, status = get_html_dom(website_url)
    # input_form_exists(html_dom)
    for i in range(10, 20):
        with open(f"./raw_htmldom_data/{i}.html", "rb") as f:
            bad_form(f.read())
    # if status is True:
    #     write_to_csv("htmldom_data.csv", website_url, html_dom, True)