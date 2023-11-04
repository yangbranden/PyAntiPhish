#!/usr/bin/python3

# Online checks (used in addition to the offline checks)
# Features extracted from script:
# 1. Malicious <form> tag (which has the following characteristics):
# an <input> tag in the form
# contains keywords in blacklist (e.g. "password", "credit card number") OR no text at all but images within the scope of the HTML form
# Malicious "action" attribute; value is among:
# Empty (capable of running JS)
# Simple (relative path) file name
# Domain different from the webpage domain
# 2. Ratio of nil anchors (href="#") to all anchors (i.e. percentage of nil anchors)
# 3. TF-IDF of page
# 4. Browser Lookup (again Google API client) for domain name + <title> tag content
# 5. Google Safe Browsing
# 6. VirusTotal API
# 7. PhishTank online-valid list check
# 8. WHOIS lookups

import requests
import os
import csv
from bs4 import BeautifulSoup

# TODO
def has_bad_form(response_content):
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response_content, 'html.parser') # response.content has the HTML DOM, we use bs4 to parse it
    print(soup.head)

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

# Write row of CSV (append)
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
                "website_url", "result"
            ])
        
        # values
        
        row = [
            url, result
        ]

        csv_writer.writerow(row)
        print("Data written to CSV file:", row)
        return True

if __name__ == "__main__":
    # website_url = input("Enter the website URL: ")
    # html_dom, status = get_html_dom(website_url)
    # input_form_exists(html_dom)
    for i in range(10, 20):
        with open(f"./raw_htmldom_data/{i}.html", "rb") as f:
            has_bad_form(f.read())
    # if status is True:
    #     write_to_csv("htmldom_data.csv", website_url, html_dom, True)