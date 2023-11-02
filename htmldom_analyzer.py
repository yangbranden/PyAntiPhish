#!/usr/bin/python3

# Stage 3 - analyze HTML DOM
# Features extracted from script:
# X. Presence of <input> and <form> tag; all phishing pages have at least one text input
# X. Presence of onclick, onload, onchange, onkeydown, onkeyup attributes
# 1. Ratio of nil anchors (href=“#”) to all anchors (i.e. percentage of nil anchors)
# 2. <head> element
# 2. "href" attribute (<a>, <area>, <base>, <link>) outside of domain 
# 3. "src" attribute (<audio>, <embed>, <iframe>, <img>, <input>, <script>, <source>, <track>, <video>) outside of domain

import requests
import os
import csv
from bs4 import BeautifulSoup

def input_form_exists(response_content):
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response_content, 'html.parser') # response.content has the HTML DOM, we use bs4 to parse it
    
    input_tags = soup.find_all('input')
    form_tags = soup.find_all('form')
    onclick_elements = soup.find_all(attrs={"onclick": True})
    onload_elements = soup.find_all(attrs={"onload": True})
    onchange_elements = soup.find_all(attrs={"onchange": True})
    onkeydown_elements = soup.find_all(attrs={"onkeydown": True})
    onkeyup_elements = soup.find_all(attrs={"onkeyup": True})
    
    # print(soup.find_all("form"), soup.find_all("input"))
    print(len(input_tags), len(form_tags), len(onclick_elements), len(onload_elements), len(onchange_elements), len(onkeydown_elements), len(onkeyup_elements))
    

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
            input_form_exists(f.read())
    # if status is True:
    #     write_to_csv("htmldom_data.csv", website_url, html_dom, True)