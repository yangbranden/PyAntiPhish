#!/usr/bin/python3

# URL-based features:
#  1. Length of domain to length of netloc (domain + subdomain)
#  2. Length of subdomain to length of netloc (domain + subdomain)
#  3. Length of path components to length of URL
#  Frequency of suspicious characters
#  4. ‘.’ count
#  5. ‘%’ count
#  6. ‘-’ count
#  7. ‘@’ count
#  8. ‘&’ count
#  9. ‘=’ count
# 10. ‘#’ count
# 11. Non-standard TLD in standard location
# 12. Standard TLD in non-standard location
# 13. Raw IP as URL
# 14. HTTPS (TLS) status
# 15. Levenshtein distance to URLs in whitelist

import csv
import os
import socket
from urllib.parse import urlparse
import pickle
import tldextract
from fuzzywuzzy import fuzz
import json

# Import feature extraction functions from url_features folder
from url_features.url_len import get_url_len
from url_features.subdomain_len_ratio import get_subdomain_len_ratio
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
                "website_url", "url_length", "subdomain_len_ratio", "pathcomp_len_ratio", "period_count", "percent_count", "dash_count", "atsign_count", 
                "ampersand_count", "equal_count", "hashsign_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", "has_tls", "typosquatting", "result"
            ])

        url_length = get_url_len(url)
        subdomain_len_ratio = get_subdomain_len_ratio(url)
        pathcomp_len_ratio = get_pathcomp_len_ratio(url)
        period_count = count_char(url, '.')
        percent_count = count_char(url, '%')
        dash_count = count_char(url, '-')
        atsign_count = count_char(url, '@')
        ampersand_count = count_char(url, '&')
        equal_count = count_char(url, '=')
        hashsign_count = count_char(url, '#')
        has_bad_tld = bad_tld(url)
        has_bad_tld_location = bad_tld_location(url)
        has_raw_ip = raw_ip_as_url(url)
        has_tls = tls_status(url)
        typosquatting = is_typosquatting(url)
        
        row = [
            url, url_length, subdomain_len_ratio, pathcomp_len_ratio, period_count, percent_count, dash_count, atsign_count, 
            ampersand_count, equal_count, hashsign_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, typosquatting, result
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
                extract_features(output_csv, row[url_index], result)
            except Exception:
                continue

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
    url_length = get_url_len(url)
    subdomain_len_ratio = get_subdomain_len_ratio(url)
    pathcomp_len_ratio = get_pathcomp_len_ratio(url)
    period_count = count_char(url, '.')
    percent_count = count_char(url, '%')
    dash_count = count_char(url, '-')
    atsign_count = count_char(url, '@')
    ampersand_count = count_char(url, '&')
    equal_count = count_char(url, '=')
    hashsign_count = count_char(url, '#')
    has_bad_tld = 1 if bad_tld(url) else 0
    has_bad_tld_location = 1 if bad_tld_location(url) else 0
    has_raw_ip = 1 if raw_ip_as_url(url) else 0
    has_tls = 1 if tls_status(url) else 0
    typosquatting = 1 if is_typosquatting(url) else 0
    
    target_url_data = [[
        url_length, subdomain_len_ratio, pathcomp_len_ratio, period_count, percent_count, dash_count, atsign_count, 
        ampersand_count, equal_count, hashsign_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, typosquatting
    ]]
    
    print(target_url_data)
    
    prediction = model.predict(target_url_data)
    print(prediction, type(prediction))
    print(f"The model predicted {url} to be {prediction[0]}.")
    
    json_format = {
        "model_selector": model_selector,
        "model_name": model_name,
        "url_length": url_length, 
        "subdomain_len_ratio": subdomain_len_ratio, 
        "pathcomp_len_ratio": pathcomp_len_ratio, 
        "period_count": period_count, 
        "percent_count": percent_count, 
        "dash_count": dash_count, 
        "atsign_count": atsign_count, 
        "ampersand_count": ampersand_count, 
        "equal_count": equal_count, 
        "hashsign_count": hashsign_count, 
        "has_bad_tld": has_bad_tld, 
        "has_bad_tld_location": has_bad_tld_location, 
        "has_raw_ip": has_raw_ip, 
        "has_tls": has_tls, 
        "typosquatting": typosquatting,
        "prediction": prediction[0]
    }
    
    return json_format

# AWS Lambda handler function
# Input format:
# {
#   "url": "https://www.google.com"
# }
def lambda_handler(json_input, lambda_context):
    website_url = json_input['url']
    
    model_LR = predict_url(website_url, 0)
    model_SVM = predict_url(website_url, 1)
    model_KNN = predict_url(website_url, 2)
    model_RF = predict_url(website_url, 3)
    
    output = {
        "model_LR": model_LR,
        "model_SVM": model_SVM,
        "model_KNN": model_KNN,
        "model_RF": model_RF
    }
    
    response = {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json'
        },
        'body': json.dumps({'output': output})
    }
    
    return response

if __name__ == "__main__":
    # TEST MODEL
    # website_url = input("Enter the website URL: ")
    website_url = "https://www.google.com/"
    
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
    
    # input = {
    #     "url": "https://www.google.com"
    # }
    # test = lambda_handler(input, None)
    # print(test['model_LR'])
    # print(test['model_SVM'])
    # print(test['model_KNN'])
    # print(test['model_RF'])
    
    # ADD DATA FROM FILE; using the extract_from_file function I made so that it is easy to create specific splits of data (and add more/less as needed)
    # extract_from_file(source_csv="./raw_url_data/raw_url_data.csv", url_index=0, result_index=1, output_csv="url_data.csv")