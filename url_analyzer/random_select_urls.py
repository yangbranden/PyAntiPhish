#!/usr/bin/env python3

import os
import csv
import random

def copy_url(output_csv, url, result):
    if os.path.exists(output_csv):
        with open(output_csv, 'r', newline='') as f:
            reader = csv.reader(f)
            
            # Only append row if url doesn't already exist
            for row in reader:
                website_url = row[0]
                if website_url == url:
                    print(f"URL {url} already found; skipping.")
                    return False
    
    with open(output_csv, 'a', newline='') as output_file:
        writer = csv.writer(output_file)
        writer.writerow([url, result])
    
    return True


def extract_from_file(source_csv, url_index, result_index, output_csv, max_rows, num_benign=10, num_phishing=1):
    if os.path.exists(output_csv):
        with open(output_csv, 'r') as f:
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
                while result != "benign":
                    row = random.choice(rows)
                    result = row[result_index]
                    if result not in ["benign"]:
                        continue
                    else:
                        result = "benign"
                try:
                    copy_url(output_csv, row[url_index], result)
                except Exception:
                    continue
            
            # Add specified number of random phishing URLs
            for _ in range(num_phishing):
                row = random.choice(rows)
                result = row[result_index]
                while result != "phishing":
                    row = random.choice(rows)
                    result = row[result_index]
                    if result not in ["phishing", "malicious", "yes"]:
                        continue
                    else:
                        result = "phishing"
                try:
                    copy_url(output_csv, row[url_index], result)
                except Exception:
                    continue
        
        with open(output_csv, 'r') as f:
            csv_reader = csv.reader(f)
            count = sum(1 for row in csv_reader)
            
if __name__ == "__main__":
    extract_from_file(source_csv="./original_sources/balanced_urls.csv", url_index=0, result_index=1, output_csv="raw_url_data.csv", max_rows=10000, num_benign=67, num_phishing=33)
    extract_from_file(source_csv="./original_sources/malicious_phish.csv", url_index=0, result_index=1, output_csv="raw_url_data.csv", max_rows=10000, num_benign=66, num_phishing=34)
    extract_from_file(source_csv="./original_sources/urldata.csv", url_index=1, result_index=2, output_csv="raw_url_data.csv", max_rows=10000, num_benign=67, num_phishing=33)
    extract_from_file(source_csv="./original_sources/online-valid.csv", url_index=1, result_index=4, output_csv="raw_url_data.csv", max_rows=10000, num_benign=0, num_phishing=100)