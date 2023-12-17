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

# Extract collected HTML DOM data
# TODO
def extract_from_file(source_csv, url_index, htmldom_index, result, output_csv):
    with open(source_csv, 'r', newline='', encoding='utf-8') as f:
        csv_reader = csv.reader(f)
        length = len(list(csv_reader))
        # for row in csv_reader:
        #     result = row[result_index]
            
        #     if result in ["benign"]:
        #         result = "benign"
        #     elif result in ["phishing", "malicious", "yes"]:
        #         result = "phishing"
            
        #     if result not in ["benign", "phishing"]:
        #         continue
            
        #     try:
        #         write_to_csv(output_csv, row[url_index], result)
        #     except Exception:
        #         continue

if __name__ == "__main__":
    # website_url = input("Enter the website URL: ")
    # html_dom, status = get_html_dom(website_url)
    pass
    
    # for i in range(10, 20):
    #     with open(f"./raw_htmldom_data/{i}.html", "rb") as f:
    #         bad_form(f.read())
    # if status is True:
    #     write_to_csv("htmldom_data.csv", website_url, html_dom, True)