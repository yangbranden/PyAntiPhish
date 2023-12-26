#!/usr/bin/python3

# HTML DOM-based features:
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

# Future improvements:
# 11. (Using WHOIS lookup API) Creation date, Expiration date 
# 12. TF-IDF of page to get term set --> Browser Lookup (Google API client) of term set + *maybe* <title> tag content

import requests
from bs4 import BeautifulSoup
import csv
import os
from urllib.parse import urlparse
import pickle
import numpy as np
import tldextract
from fuzzywuzzy import fuzz
import random

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

# Feature 10: TF-IDF of page to get keywords (mostly looking for brand/company name) + google search
# Potential future implementation for when I obtain a larger cranium

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

# Extract features from requests.get response; write to output CSV
def extract_features_online(filename, url, result):
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
        if response.status_code != 200:
            return False

        if not file_exists:
            # Write header row
            csv_writer.writerow([
                "website_url", "has_bad_form", "asks_username_email", "asks_password", "asks_phone", "asks_birthday", "asks_card_info", "asks_ssn", "has_bad_action", "nil_anchors",
                "result"
            ])
            
        has_bad_form = bad_form(response)
        asks_username_email = asks_for_pii(response, ["login", "username", "email", "email address", "e-mail", "e-mail address"])
        asks_password = asks_for_pii(response, ["password", "passphrase", "passcode", "pin", "pin number"])
        asks_phone = asks_for_pii(response, ["phone number", "telephone number", "mobile number", "cell phone number"])
        asks_birthday = asks_for_pii(response, ["birthday", "birth day", "birth date", "date of birth", "dob", "bday"])
        asks_card_info = asks_for_pii(response, ["credit card", "credit card number", "debit card", "debit card number", "card number", "card verification", "card verification value", "cvv", "expiration date", "expiry date"])
        asks_ssn = asks_for_pii(response, ["social security number", "social security", "ssn", "ssn id", "ssn digits"])
        has_bad_action = bad_action(response, url)
        nil_anchors = nil_anchor_ratio(response)
        
        row = [
            url, has_bad_form, asks_username_email, asks_password, asks_phone, asks_birthday, asks_card_info, asks_ssn, has_bad_action, nil_anchors,
            result
        ]

        csv_writer.writerow(row)
        # print("Data written to CSV file:", row)
        return True

# Extract features from stored HTML DOM; write to output CSV
# This is for the saved phishing HTML DOMs (but could technically also be used for saved benign HTML DOMs if wanted)
def extract_features_offline(filename, url, htmldom_filepath, result):
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

        # Get stored HTML DOM from file location; exit if not found
        try:
            htmldom_file = open(htmldom_filepath, 'r')
            html_dom = htmldom_file.read()
        except FileNotFoundError:
            return False

        if not file_exists:
            # Write header row
            csv_writer.writerow([
                "website_url", "has_bad_form", "asks_username_email", "asks_password", "asks_phone", "asks_birthday", "asks_card_info", "asks_ssn", "has_bad_action", "nil_anchors",
                "result"
            ])
            
        has_bad_form = bad_form(html_dom)
        asks_username_email = asks_for_pii(html_dom, ["login", "username", "email", "email address", "e-mail", "e-mail address"])
        asks_password = asks_for_pii(html_dom, ["password", "passphrase", "passcode", "pin", "pin number"])
        asks_phone = asks_for_pii(html_dom, ["phone number", "telephone number", "mobile number", "cell phone number"])
        asks_birthday = asks_for_pii(html_dom, ["birthday", "birth day", "birth date", "date of birth", "dob", "bday"])
        asks_card_info = asks_for_pii(html_dom, ["credit card", "credit card number", "debit card", "debit card number", "card number", "card verification", "card verification value", "cvv", "expiration date", "expiry date"])
        asks_ssn = asks_for_pii(html_dom, ["social security number", "social security", "ssn", "ssn id", "ssn digits"])
        has_bad_action = bad_action(html_dom, url)
        nil_anchors = nil_anchor_ratio(html_dom)
        
        row = [
            url, has_bad_form, asks_username_email, asks_password, asks_phone, asks_birthday, asks_card_info, asks_ssn, has_bad_action, nil_anchors,
            result
        ]

        csv_writer.writerow(row)
        # print("Data written to CSV file:", row)
        return True

# Extract features from collected HTML DOM data
def extract_from_file(source_csv, url_index, htmldom_index, result_index, output_csv, max_rows, num_benign=10, num_phishing=1):
    if os.path.exists(output_csv):
        with open(output_csv, 'r', encoding='latin-1') as f:
            csv_reader = csv.reader(f)
            count = sum(1 for row in csv_reader)
    else:
        count = 0
    target_count = count + max_rows
    while count < target_count:
        with open(source_csv, 'r', newline='', encoding='latin-1') as f:
            csv_reader = csv.reader(f)
            rows = list(csv_reader)
            
            # Add specified number of random benign URLs
            for _ in range(num_benign):
                row = random.choice(rows)
                result = row[result_index]
                print("Attempting benign URL:", row[url_index])
                while result != "False":
                    print("Invalid.\n")
                    row = random.choice(rows)
                    print("Attempting benign URL:", row[url_index])
                    # if the URL doesn't start with https:// then skip it because it is an outlier
                    url = row[url_index]
                    if not url.startswith("https://"):
                        continue
                    result = row[result_index]
                try:
                    extract_features_online(output_csv, row[url_index], result)
                except Exception:
                    continue
            
            # Add specified number of random phishing URL
            for _ in range(num_phishing):
                row = random.choice(rows)
                result = row[result_index]
                print("Attempting phishing URL:", row[url_index])
                while result != "True":
                    print("Invalid.\n")
                    row = random.choice(rows)
                    print("Attempting phishing URL:", row[url_index])
                    result = row[result_index]
                try:
                    extract_features_offline(output_csv, row[url_index], row[htmldom_index], result)
                except Exception:
                    continue
        
        with open(output_csv, 'r') as f:
            csv_reader = csv.reader(f)
            count = sum(1 for row in csv_reader)

if __name__ == "__main__":
    # TEST MODEL
    # website_url = input("Enter the website URL: ")
    # html_dom, status = get_html_dom(website_url)
    
    # ADD DATA
    extract_from_file(source_csv="raw_htmldom_data.csv", url_index=0, htmldom_index=1, result_index=2, output_csv="htmldom_data.csv", max_rows=5000, num_benign=0, num_phishing=100)
