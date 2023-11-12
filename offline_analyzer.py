#!/usr/bin/python3

# Offline checks (URL only)
# Features extracted from script:
#  1. Length of URL
#  2. Length of netloc (domain + subdomain)
#  3. Length of path components
#  Frequency of non-alphanumeric (possibly suspicious) characters (‘.’, ‘/’, ‘%’, ‘-’, ‘?’, ‘!’, ‘@’, ‘,’, ‘&’, ‘#’, ‘=’, ‘_’, ‘+’, ‘:’, ‘;’)
#  4. ‘.’ count
#  5. ‘/’ count
#  6. ‘%’ count
#  7. ‘-’ count
#  8. ‘?’ count
#  9. ‘!’ count
# 10. ‘@’ count
# 11. ‘,’ count
# 12. ‘&’ count
# 13. ‘#’ count
# 14. ‘=’ count
# 15. ‘_’ count
# 16. ‘+’ count
# 17. ‘:’ count
# 18. ‘;’ count
# 19. ‘~’ count
# 20. ‘&’ count
# 21. Non-standard TLD in standard location
# 22. Standard TLD in non-standard location
# 23. Raw IP as URL
# 24. HTTPS (TLS) status
# 25. Levenshtein distance to URLs in whitelist

import csv
import os
import socket
from urllib.parse import urlparse
import pickle
import numpy as np
import random
import tldextract
from fuzzywuzzy import fuzz

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

########################################################################################################################################################

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

        if not file_exists:
            # Write header row
            csv_writer.writerow([
                "website_url", "url_length", "netloc_length", "pathcomp_length", "period_count", "slash_count", "percent_count", "dash_count", "underscore_count", 
                "question_count", "ampersand_count", "hashsign_count", "exclamation_count", "atsign_count", "comma_count", "equal_count", "plus_count", 
                "colon_count", "semicolon_count", "tilde_count", "dollar_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", "has_tls", "typosquatting", "result"
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
        
        row = [
            url, url_length, netloc_length, pathcomp_length, period_count, slash_count, percent_count, dash_count, underscore_count, 
            question_count, ampersand_count, hashsign_count, exclamation_count, atsign_count, comma_count, equal_count, plus_count, 
            colon_count, semicolon_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, typosquatting, result
        ]

        csv_writer.writerow(row)
        # print("Data written to CSV file:", row)
        return True

# Get results from existing datasets (add entire csv)
def extract_from_file(source_csv, url_index, result_index, output_csv):
    with open(source_csv, 'r', newline='', encoding='utf-8') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            result = row[result_index]
            
            if result in ["benign"]:
                result = "benign"
            elif result in ["phishing", "malicious", "yes"]:
                result = "phishing"
            
            if result not in ["benign", "phishing"]:
                continue
            
            try:
                write_to_csv(output_csv, row[url_index], result)
            except Exception:
                continue

# Get random rows from csv file (random sample selection); default split of 10 benign to 1 phishing
def extract_from_file(source_csv, url_index, result_index, output_csv, max_rows, num_benign=10, num_phishing=1):
    if os.path.exists(output_csv):
        with open(output_csv, 'r') as f:
            csv_reader = csv.reader(f)
            count = sum(1 for row in csv_reader)
    else:
        count = 0
    target_count = count + max_rows
    while count < target_count:
        with open(source_csv, 'r', newline='', encoding='utf-8') as f:
            csv_reader = csv.reader(f)
            rows = list(csv_reader)
            
            # Add specified number of random benign URLs
            for _ in range(num_benign):
                row = random.choice(rows)
                result = row[result_index]
                while result != "benign":
                    row = random.choice(rows)
                    result = row[result_index]
                    if result in ["benign"]:
                        result = "benign"
                    elif result in ["phishing", "malicious", "yes"]:
                        result = "phishing"
                    if result not in ["benign", "phishing"]:
                        continue
                try:
                    write_to_csv(output_csv, row[url_index], result)
                except Exception:
                    continue
            
            # Add specified number of random phishing URL
            for _ in range(num_phishing):
                row = random.choice(rows)
                result = row[result_index]
                while result != "phishing":
                    row = random.choice(rows)
                    result = row[result_index]
                    if result in ["benign"]:
                        result = "benign"
                    elif result in ["phishing", "malicious", "yes"]:
                        result = "phishing"
                    if result not in ["benign", "phishing"]:
                        continue
                try:
                    write_to_csv(output_csv, row[url_index], result)
                except Exception:
                    continue
        
        with open(output_csv, 'r') as f:
            csv_reader = csv.reader(f)
            count = sum(1 for row in csv_reader)
            
# Use ML model(s) to read data and predict
def predict_url(url, model_selector):
    if model_selector == 0: # Logistic Regression
        model_name = "offline_model_LR.pickle"
    elif model_selector == 1: # SVM
        model_name = "offline_model_SVM.pickle"
    elif model_selector == 2: # KNN
        model_name = "offline_model_KNN.pickle"
    elif model_selector == 3: # Random Forest
        model_name = "offline_model_RF.pickle"
        
    # Read the model from the pickle file
    try:
        saved_model = open(model_name, "rb")
        model = pickle.load(saved_model)
    except FileNotFoundError:
        print("Model not found.")
        exit()
    
    # Get the necessary data points from the URL
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
    has_bad_tld = 1 if bad_tld(url) else 0
    has_bad_tld_location = 1 if bad_tld_location(url) else 0
    has_raw_ip = 1 if raw_ip_as_url(url) else 0
    has_tls = 1 if tls_status(url) else 0
    typosquatting = 1 if is_typosquatting(url) else 0
    
    target_url_data = np.array([[
        url_length, netloc_length, pathcomp_length, period_count, slash_count, percent_count, dash_count, underscore_count, 
        question_count, ampersand_count, hashsign_count, exclamation_count, atsign_count, comma_count, equal_count, plus_count, 
        colon_count, semicolon_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, typosquatting
    ]])
    
    print(target_url_data)
    
    prediction = model.predict(target_url_data)
    print(f"The model predicted {url} to be {prediction[0]}.")

if __name__ == "__main__":
    # TEST MODEL
    # website_url = input("Enter the website URL: ")
    
    # print("LR")
    # predict_url(website_url, 0)
    # print()
    # print("SVM")
    # predict_url(website_url, 1)
    # print()
    # print("KNN")
    # predict_url(website_url, 2)
    # print()
    # print("RF")
    # predict_url(website_url, 3)
    # print()
    
    # ADD DATA FROM FILE; using the extract_from_file function I made so that it is easy to create specific splits of data (and add more/less as needed)
    extract_from_file(source_csv="./raw_url_data/balanced_urls.csv", url_index=0, result_index=1, output_csv="offline_data.csv", max_rows=5000, num_benign=100, num_phishing=10)
    extract_from_file(source_csv="./raw_url_data/malicious_phish.csv", url_index=0, result_index=1, output_csv="offline_data.csv", max_rows=5000, num_benign=100, num_phishing=10)
    extract_from_file(source_csv="./raw_url_data/urldata.csv", url_index=1, result_index=2, output_csv="offline_data.csv", max_rows=5000, num_benign=100, num_phishing=10)
    extract_from_file(source_csv="./raw_url_data/online-valid.csv", url_index=1, result_index=4, output_csv="offline_data.csv", max_rows=5000, num_benign=0, num_phishing=100)