#!/usr/bin/env python3

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn import metrics
from sklearn.model_selection import train_test_split
import pickle

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

# This function calculates all of the metrics that we want to see from our model, as well as displays a correlation matrix heatmap
def calculate_metrics():
    print("\n### EXPERIMENT 3 ###\n\n")
    data = pd.read_csv("url3_data.csv", encoding='latin-1')
    for model_name in ["url3_model_LR.pickle", "url3_model_SVM.pickle", "url3_model_KNN.pickle", "url3_model_RF.pickle"]:
        if model_name == "url3_model_LR.pickle": # Logistic Regression
            features = np.array(data[["netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "percent_count", "atsign_count", "hashsign_count", "plus_count", 
                "semicolon_count", "comma_count", "exclamation_count", "dollar_count", "has_bad_tld", "has_raw_ip", "typosquatting"]])
        elif model_name == "url3_model_SVM.pickle": # Support Vector Machine
            features = np.array(data[["netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "percent_count", "question_count", "atsign_count", "hashsign_count", "plus_count", 
                "comma_count", "exclamation_count", "dollar_count", "has_bad_tld", "has_raw_ip", "typosquatting"]])
        elif model_name == "url3_model_KNN.pickle": # K-Nearest Neighbors
            features = np.array(data[["subdomain_len", "netloc_len_ratio", "pathcomp_len_ratio", "period_count", "dash_count", "atsign_count", "plus_count", 
                "colon_count", "exclamation_count", "dollar_count", "has_bad_tld", "has_raw_ip", "has_tls", "typosquatting"]])
        elif model_name == "url3_model_RF.pickle": # Random Forest
            features = np.array(data[["url_length", "subdomain_len", "subdomain_len_ratio", "netloc_len", "netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "period_count",
                    "slash_count", "percent_count", "dash_count", "question_count", "atsign_count", "ampersand_count", "hashsign_count", "equal_count", "underscore_count", "plus_count", 
                    "colon_count", "semicolon_count", "comma_count", "exclamation_count", "tilde_count", "dollar_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", 
                    "has_tls", "typosquatting"]])
        labels = np.array(data["result"])
        x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)
        saved_model = open(model_name, "rb")
        model = pickle.load(saved_model)
        predictions = model.predict(x_test)
        
        accuracy = metrics.accuracy_score(y_test, predictions)
        precision = metrics.precision_score(y_test, predictions, pos_label="phishing")
        recall = metrics.recall_score(y_test, predictions, pos_label="phishing")
        f1_score = metrics.f1_score(y_test, predictions, pos_label="phishing")
        tn, fp, fn, tp = metrics.confusion_matrix(y_test, predictions).ravel()
        print(model_name)
        print("Accuracy:", accuracy)
        print("Precision:", precision) # tp / (tp + fp)
        print("Recall:", recall) # tp / (tp + fn)
        print("F1 score:", f1_score) # 2 * tp / (2 * tp + fn + fp)
        print("False Positive Rate:", fp / (fp + tn))
        print("False Negative Rate:", fn / (fn + tp))
        
        cm = metrics.confusion_matrix(y_test, predictions)
        disp = metrics.ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['benign', 'phishing'])
        disp.plot()
        plt.title('Experiment 3 - Confusion Matrix of ' + model_name)
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.text(0, 0.4, 'True Negative', ha='center')
        plt.text(1, 0.4, 'False Positive', ha='center', color='white')
        plt.text(0, 1.4, 'False Negative', ha='center', color='white')
        plt.text(1, 1.4, 'True Positive', ha='center')
        plt.show()
        print()


# This method can be used to manually test a specific URL, just as a more hands-on way of testing things
def predict_url(url, model_selector):
    if model_selector == 0: # Logistic Regression
        model_name = "url3_model_LR.pickle"
    elif model_selector == 1: # SVM
        model_name = "url3_model_SVM.pickle"
    elif model_selector == 2: # KNN
        model_name = "url3_model_KNN.pickle"
    elif model_selector == 3: # Random Forest
        model_name = "url3_model_RF.pickle"
        
    # Read the model from the pickle file
    try:
        saved_model = open(model_name, "rb")
        model = pickle.load(saved_model)
    except FileNotFoundError:
        print("Model not found.")
        exit()
    
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
    
    if model_selector == 0: # Logistic Regression
        target_url_data = [[
            netloc_len_ratio, pathcomp_len, pathcomp_len_ratio, percent_count, atsign_count, hashsign_count, plus_count, 
            semicolon_count, comma_count, exclamation_count, dollar_count, has_bad_tld, has_raw_ip, typosquatting
        ]]
    elif model_selector == 1: # SVM
        target_url_data = [[
            netloc_len_ratio, pathcomp_len, pathcomp_len_ratio, percent_count, question_count, atsign_count, hashsign_count, plus_count, 
            comma_count, exclamation_count, dollar_count, has_bad_tld, has_raw_ip, typosquatting
        ]]
    elif model_selector == 2: # KNN
        target_url_data = [[
            subdomain_len, netloc_len_ratio, pathcomp_len_ratio, period_count, dash_count, atsign_count, plus_count, 
            colon_count, exclamation_count, dollar_count, has_bad_tld, has_raw_ip, has_tls, typosquatting
        ]]
    elif model_selector == 3: # Random Forest
        target_url_data = [[
            url_length, subdomain_len, subdomain_len_ratio, netloc_len, netloc_len_ratio, pathcomp_len, pathcomp_len_ratio, period_count, slash_count,
            percent_count, dash_count, question_count, atsign_count, ampersand_count, hashsign_count, equal_count, underscore_count, plus_count, colon_count,
            semicolon_count, comma_count, exclamation_count, tilde_count, dollar_count, has_bad_tld, has_bad_tld_location, has_raw_ip, has_tls, typosquatting
        ]]
    
    print(target_url_data)
    
    prediction = model.predict(target_url_data)
    print(prediction, type(prediction))
    print(f"The model predicted {url} to be {prediction[0]}.")

    
if __name__ == "__main__":
    # TEST MODEL MANUALLY
    # website_url = input("Enter the website URL: ")
    # website_url = "https://www.google.com/"
    
    # print("LR")
    # predict_url(website_url, 0)
    # print()
    # print("SVM")
    # predict_url(website_url, 1)
    # print()
    # print("KNN")
    # predict_url(website_url, 2)
    # print()
    # print("RF")
    # predict_url(website_url, 3)
    # print()
    
    calculate_metrics()