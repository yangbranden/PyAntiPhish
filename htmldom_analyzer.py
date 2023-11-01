#!/usr/bin/python3

# Stage 3 - analyze HTML DOM
# Features extracted from script:
# 1. presence of <input> or <form> tag
# 2. ratio of nil hrefs to total (href="#" attributes)
# 3. redirect anchors
# 4. 

import requests
import os
import csv
from bs4 import BeautifulSoup
    
def parse_htmldom(response_content):
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response_content, 'html.parser') # response.content has the HTML DOM, we use bs4 to parse it

# THIS IS TO GATHER THE RAW DATA BECAUSE PHISHING PAGES GET DELETED QUICKLY SO I AM GOING TO SAVE THE FULL DOM
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
def write_to_csv(filename, url, html_dom, result):
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
                "website_url", "html_dom", "result"
            ])
        
        row = [
            url, html_dom, result
        ]

        csv_writer.writerow(row)
        print("Data written to CSV file:", row)
        return True

if __name__ == "__main__":
    with open("phishing_sites.txt", "r") as f:
        for url in f:
            url = url.rstrip('\n')
            html_dom, status = get_html_dom(url)
            print(html_dom, status)
            if status is True:
                write_to_csv("raw_htmldom_data.csv", url, html_dom, True)