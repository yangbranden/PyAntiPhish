#!/usr/bin/env python3

import csv
import os
from urllib.parse import urlparse

# so that we can import our features
import sys
sys.path.append("../../")

# Import feature extraction functions from url_features folder
from url_features.url_len import get_url_len
from url_features.subdomain_len import get_subdomain_len
from url_features.subdomain_len_ratio import get_subdomain_len_ratio
from url_features.netloc_len import get_netloc_len
from url_features.netloc_len_ratio import get_netloc_len_ratio
from url_features.pathcomp_len import get_pathcomp_len
from url_features.pathcomp_len_ratio import get_pathcomp_len_ratio
from url_features.count_char import count_char
from url_features.bad_tld import bad_tld
from url_features.bad_tld_location import bad_tld_location
from url_features.raw_ip_as_url import raw_ip_as_url
from url_features.tls_status import tls_status
from url_features.is_typosquatting import is_typosquatting

# Extract features and write to output CSV
def extract_features(filename, url, result):
    file_exists = os.path.exists(filename)
    
    # Open file as append (creates file if doesn't exist)
    with open(filename, 'a', newline='') as f:
        csv_writer = csv.writer(f)

        if not file_exists:
            # Write header row
            csv_writer.writerow([
                "website_url", 
                "url_length", 
                "subdomain_len", 
                "subdomain_len_ratio", 
                "netloc_len", 
                "netloc_len_ratio", 
                "pathcomp_len", 
                "pathcomp_len_ratio", 
                "period_count",
                "slash_count",
                "percent_count", 
                "dash_count", 
                "question_count", 
                "atsign_count", 
                "ampersand_count", 
                "hashsign_count", 
                "equal_count", 
                "underscore_count", 
                "plus_count", 
                "colon_count", 
                "semicolon_count", 
                "comma_count", 
                "exclamation_count", 
                "tilde_count", 
                "dollar_count", 
                "has_bad_tld", 
                "has_bad_tld_location", 
                "has_raw_ip", 
                "has_tls", 
                "typosquatting", 
                "result"
            ])

        url_length = get_url_len(url)
        subdomain_len = get_subdomain_len(url)
        subdomain_len_ratio = get_subdomain_len_ratio(url)
        netloc_len = get_netloc_len(url) 
        netloc_len_ratio = get_netloc_len_ratio(url) 
        pathcomp_len = get_pathcomp_len(url)
        pathcomp_len_ratio = get_pathcomp_len_ratio(url)
        period_count = count_char(url, '.')
        slash_count = count_char(url, '/')
        percent_count = count_char(url, '%')
        dash_count = count_char(url, '-')
        question_count = count_char(url, '?')
        atsign_count = count_char(url, '@')
        ampersand_count = count_char(url, '&')
        hashsign_count = count_char(url, '#')
        equal_count = count_char(url, '=')
        underscore_count = count_char(url, '_')
        plus_count = count_char(url, '+')
        colon_count = count_char(url, ':')
        semicolon_count = count_char(url, ';')
        comma_count = count_char(url, ',')
        exclamation_count = count_char(url, '!')
        tilde_count = count_char(url, '~')
        dollar_count = count_char(url, '$')
        has_bad_tld = bad_tld(url) 
        has_bad_tld_location = bad_tld_location(url)
        has_raw_ip = raw_ip_as_url(url)
        has_tls = tls_status(url)
        typosquatting = is_typosquatting(url)
        
        row = [
            url, 
            url_length,
            subdomain_len,
            subdomain_len_ratio,
            netloc_len,
            netloc_len_ratio,
            pathcomp_len,
            pathcomp_len_ratio,
            period_count,
            slash_count,
            percent_count,
            dash_count,
            question_count,
            atsign_count,
            ampersand_count,
            hashsign_count,
            equal_count,
            underscore_count,
            plus_count,
            colon_count,
            semicolon_count,
            comma_count,
            exclamation_count,
            tilde_count,
            dollar_count,
            has_bad_tld, 
            has_bad_tld_location,
            has_raw_ip,
            has_tls,
            typosquatting, 
            result
        ]

        csv_writer.writerow(row)
        # print("Data written to CSV file:", row)
        return True

# Get results from existing datasets (add entire csv)
def extract_from_file(source_csv, url_index, result_index, output_csv):
    with open(source_csv, 'r', newline='', encoding='latin-1') as f:
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
                extract_features(output_csv, row[url_index], result)
            except Exception:
                continue

if __name__ == "__main__":
    # ADD DATA FROM FILE; using the extract_from_file function I made so that it is easy to create specific splits of data (and add more/less as needed)
    extract_from_file(source_csv="../../raw_url_data/raw_url_data.csv", url_index=0, result_index=1, output_csv="url1_data.csv")