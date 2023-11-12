#!/usr/bin/python3

import requests
import os
import csv
import pandas as pd

# THIS IS TO GATHER THE RAW DATA BECAUSE PHISHING PAGES GET DELETED QUICKLY SO I AM GOING TO SAVE THE FULL DOM
# DOWNLOAD PHISHTANK DATA: http://data.phishtank.com/data/online-valid.csv
def get_html_dom(url):
    try:
        # Send a GET request to the URL
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
            "Accept-Encoding": "*",
            "Connection": "keep-alive"
        }
        response = requests.get(url, headers=headers)
        # Check if the request was successful (status code 200)
        if response.status_code == 200:
            # the name of the saved HTML DOM will be the current length of the CSV file (so the folder & csv file MUST match)
            with open("raw_htmldom_data.csv", "r") as f:
                index = len(f.readlines())
            # basically we save the data to a directory (separate file for each HTML DOM)
            dirpath = "./raw_htmldom_data"
            filepath = os.path.join(dirpath, f"{index}.html")
            print(f"Saved HTML DOM of {url} to {filepath}")
            if not os.path.exists(dirpath):
                os.makedirs(dirpath)
            with open(filepath, "wb") as f:
                f.write(response.content)
            # then return the filepath to store in the CSV file
            return filepath, True
        else:
            return None, False
    except Exception as e:
        print(f"Failed to get HTML DOM for {url}")
        return None, False

# Write row of CSV (append)
def write_to_csv(filename, url, html_dom_path, result):
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
                "website_url", "html_dom_path", "result"
            ])
        
        row = [
            url, html_dom_path, result
        ]

        csv_writer.writerow(row)
        print("Data written to CSV file:", row)
        return True

    

if __name__ == "__main__":
    with open("online-valid.csv", "r") as f:
        reader = csv.reader(f)
        for row in reader:
            url = row[1]
            # Write header row if file doesn't exist
            if not os.path.exists("raw_htmldom_data.csv"):
                csv.writer(open("raw_htmldom_data.csv", "w")).writerow([
                    "website_url", "html_dom_path", "result"
                ])
            
            # skip if already in file
            saved_data = pd.read_csv("raw_htmldom_data.csv")
            urls_column = saved_data['website_url'].tolist()
            if url in urls_column:
                print("URL already found; skipping")
                continue
            html_dom_path, status = get_html_dom(url)
            if status is True and os.path.exists(html_dom_path):
                write_to_csv("raw_htmldom_data.csv", url, html_dom_path, True)