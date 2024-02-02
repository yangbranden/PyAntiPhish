#!/usr/bin/env python3

import pickle
import json

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
   
# Use ML model(s) to read data and predict
def predict_url(url, model_selector):
    if model_selector not in [-1, 0, 1, 2, 3]:
        return {"error": "Model not found."}
    
    if model_selector == 0: # Logistic Regression
        model_name = "url_model_LR.pickle"
    elif model_selector == 1: # SVM
        model_name = "url_model_SVM.pickle"
    elif model_selector == 2: # KNN
        model_name = "url_model_KNN.pickle"
    elif model_selector == 3: # Random Forest
        model_name = "url_model_RF.pickle"
    
    # Get the necessary data points from the URL
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
    has_bad_tld = 1 if bad_tld(url) else 0
    has_bad_tld_location = 1 if bad_tld_location(url) else 0
    has_raw_ip = 1 if raw_ip_as_url(url) else 0
    has_tls = 1 if tls_status(url) else 0
    typosquatting = 1 if is_typosquatting(url) else 0
    
    if model_selector == -1:
        json_format = {
            "url_length": url_length,
            "subdomain_len": subdomain_len,
            "subdomain_len_ratio": subdomain_len_ratio,
            "netloc_len": netloc_len,
            "netloc_len_ratio": netloc_len_ratio, 
            "pathcomp_len": pathcomp_len,
            "pathcomp_len_ratio": pathcomp_len_ratio,
            "period_count": period_count,
            "slash_count": slash_count,
            "percent_count": percent_count,
            "dash_count": dash_count,
            "question_count": question_count,
            "atsign_count": atsign_count,
            "ampersand_count": ampersand_count,
            "hashsign_count": hashsign_count,
            "equal_count": equal_count,
            "underscore_count": underscore_count, 
            "plus_count": plus_count,
            "colon_count": colon_count, 
            "semicolon_count": semicolon_count, 
            "comma_count": comma_count,
            "exclamation_count": exclamation_count,
            "tilde_count": tilde_count, 
            "dollar_count": dollar_count,
            "has_bad_tld": has_bad_tld,
            "has_bad_tld_location": has_bad_tld_location,
            "has_raw_ip": has_raw_ip,
            "has_tls": has_tls,
            "typosquatting": typosquatting
        }
        return json_format
    
    # Read the model from the pickle file
    try:
        saved_model = open(model_name, "rb")
        model = pickle.load(saved_model)
    except FileNotFoundError:
        return {"error": "Model not found."}
    
    if model_selector == 0: # Logistic Regression
        target_url_data = [[
            url_length, subdomain_len_ratio, netloc_len, netloc_len_ratio, pathcomp_len, pathcomp_len_ratio, period_count,
            slash_count, percent_count, dash_count, question_count, atsign_count, ampersand_count, hashsign_count, equal_count, underscore_count, plus_count, 
            colon_count, comma_count, exclamation_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_tls, typosquatting
        ]]
    elif model_selector == 1: # SVM
        target_url_data = [[
            url_length, subdomain_len_ratio, netloc_len, netloc_len_ratio, pathcomp_len, pathcomp_len_ratio, period_count,
            slash_count, percent_count, dash_count, atsign_count, ampersand_count, hashsign_count, equal_count, underscore_count, plus_count, 
            colon_count, comma_count, exclamation_count, dollar_count, has_bad_tld, has_bad_tld_location, has_tls, typosquatting
        ]]
    elif model_selector == 2: # KNN
        target_url_data = [[
            subdomain_len, subdomain_len_ratio, pathcomp_len_ratio, period_count, question_count, atsign_count, colon_count, comma_count, 
            exclamation_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, typosquatting
        ]]
    elif model_selector == 3: # Random Forest
        target_url_data = [[
            url_length, subdomain_len, subdomain_len_ratio, netloc_len, netloc_len_ratio, pathcomp_len_ratio, period_count,
            slash_count, percent_count, dash_count, question_count, atsign_count, ampersand_count, hashsign_count, equal_count, underscore_count, plus_count, 
            colon_count, semicolon_count, comma_count, exclamation_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, 
            has_tls, typosquatting
        ]]
    
    # print(target_url_data)
    
    prediction = model.predict(target_url_data)
    # print(prediction, type(prediction))
    # print(f"The model predicted {url} to be {prediction[0]}.")
    
    json_format = {
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
    features = predict_url(website_url, -1)
    
    body = {
        "model_LR": model_LR,
        "model_SVM": model_SVM,
        "model_KNN": model_KNN,
        "model_RF": model_RF,
        "features": features
    }
    
    response = {
        'statusCode': 200,
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json'
        },
        'body': json.dumps(body)
    }
    
    return response