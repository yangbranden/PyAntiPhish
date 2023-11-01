#!/usr/bin/python3

# Stage 1 - analyze URL
# Features extracted from script:
#  1. Length of URL
#  2. Length of netloc (only domain + subdomain)
#  Frequency of non-alphanumeric (possibly suspicious) characters (‘.’, ‘/’, ‘%’, ‘-’, ‘?’, ‘!’, ‘@’, ‘,’, ‘&’, ‘#’, ‘=’, ‘_’, ‘+’, ‘:’, ‘;’)
#  3. ‘.’ count
#  4. ‘/’ count
#  5. ‘%’ count
#  6. ‘-’ count
#  7. ‘?’ count
#  8. ‘!’ count
#  9. ‘@’ count
# 10. ‘,’ count
# 11. ‘&’ count
# 12. ‘#’ count
# 13. ‘=’ count
# 14. ‘_’ count
# 15. ‘+’ count
# 16. ‘:’ count
# 17. ‘;’ count
# 18. ‘~’ count
# 19. ‘&’ count
# 20. Non-standard TLD in standard location
# 21. Standard TLD in non-standard location
# 22. Raw IP as URL
# 23. HTTPS (TLS) status
# 24. Typosquatting (Levenshtein distance from target brand listed on PhishTank)

import requests
import csv
import os
import socket
from urllib.parse import urlparse
import pickle
import numpy as np

# Feature 1 is just len() function
# Feature 2 is len(urlparse().netloc)
def get_netloc_len(url):
    # Ensure urlparse is able to get netloc properly
    if not (url.startswith('//') or url.startswith('http://') or url.startswith('https://')):
        url = '//' + url
    
    netloc_len = len(urlparse(url).netloc)
    
    return netloc_len

# Features 3-19 (character count)
def count_char(url, char):
    count = 0
    for c in url:
        if c == char:
            count += 1
    return count

# Feature 20 (Non-standard TLD in standard location)
def bad_tld(url):
    # Define good TLDs to check
    good_tlds = ["com", "org", "net", "edu", "gov", "co", "uk", "eu", "ca", "de", "br", "jp"]
    
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

# Feature 21 (Standard TLD in non-standard location)
def bad_tld_location(url):
    # Define good TLDs to check
    good_tlds = ["com", "org", "net", "edu", "gov", "co", "uk", "eu", "ca", "de", "br", "jp"]

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

# Feature 22 (Raw IP as URL (netloc))
def raw_ip_as_url(url):
    # Extract the netloc (network location) part from the parsed URL
    domain = urlparse(url).netloc
    
    try:
        # inet_aton gives socket error if not valid IPv4 address
        socket.inet_aton(domain)
        return True
    except socket.error:
        return False

# Feature 23 (HTTPS/TLS status)
def tls_status(url):
    # Parse the URL
    parsed_url = urlparse(url)

    # Check if the scheme is "https"
    return parsed_url.scheme == "https"

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
                    print("URL already found; skipping.")
                    return False

    # Open file as append (creates file if doesn't exist)
    with open(filename, 'a', newline='') as f:
        csv_writer = csv.writer(f)

        if not file_exists:
            # Write header row
            csv_writer.writerow([
                "website_url", "url_length", "netloc_length", "period_count", "slash_count", "percent_count", "dash_count", "underscore_count", 
                "question_count", "ampersand_count", "hashsign_count", "exclamation_count", "atsign_count", "comma_count", "equal_count", "plus_count", 
                "colon_count", "semicolon_count", "tilde_count", "dollar_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", "has_tls", "result"
            ])

        url_length = len(url)
        netloc_length = get_netloc_len(url)
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
        
        row = [
            url, url_length, netloc_length, period_count, slash_count, percent_count, dash_count, underscore_count, 
            question_count, ampersand_count, hashsign_count, exclamation_count, atsign_count, comma_count, equal_count, plus_count, 
            colon_count, semicolon_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, result
        ]

        csv_writer.writerow(row)
        print("Data written to CSV file:", row)
        return True

# Get results from existing datasets
def get_result(existing_dataset, result_index):
    with open(existing_dataset, 'r', newline='', encoding='utf-8') as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            result = row[result_index]
            if result not in ["benign", "phishing"]:
                continue
            write_to_csv("url_data.csv", row[0], result)

# Use ML model(s) to read data and predict
def predict_url(url, model_selector):
    if model_selector == 0: # Logistic Regression
        model_name = "url_model_LR.pickle"
    elif model_selector == 1: # SVM
        model_name = "url_model_SVM.pickle"
    elif model_selector == 2: # KNN
        model_name = "url_model_KNN.pickle"
    elif model_selector == 3: # Random Forest
        model_name = "url_model_RF.pickle"
        
    # Read the model from the pickle file
    try:
        saved_model = open(model_name, "rb")
        model = pickle.load(saved_model)
    except FileNotFoundError:
        print("Model not found.")
        exit()
    
    # Get the necessary data points from the URL
    url_length = len(url)
    netloc_length = get_netloc_len(url)
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
    
    target_url_data = np.array([[
        url_length, netloc_length, period_count, slash_count, percent_count, dash_count, underscore_count, question_count, 
        ampersand_count, hashsign_count, exclamation_count, atsign_count, comma_count, equal_count, plus_count, colon_count, 
        semicolon_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls
    ]])
    
    print(target_url_data)
    
    prediction = model.predict(target_url_data)
    print(f"The model predicted {url} to be {prediction[0]}.")

if __name__ == "__main__":
    # TEST MODEL
    website_url = input("Enter the website URL: ")
    # model_selector = int(input("Model #: "))
    
    # Check if able to connect
    # try:
    #     response = requests.get(url)
    #     if response.status_code != 200:
    #         print("Failed to retrieve the website:", url)
    #         return False
    # except requests.exceptions.RequestException:
    #     print("Failed to connect to the website:", url)
    #     return False
    
    print("LR")
    predict_url(website_url, 0)
    print()
    print("SVM")
    predict_url(website_url, 1)
    print()
    print("KNN")
    predict_url(website_url, 2)
    print()
    print("RF")
    predict_url(website_url, 3)
    print()
    
    # ADD DATA FROM FILE
    # csv_filename = "raw_url_data.csv"
    # get_result(csv_filename, 1)