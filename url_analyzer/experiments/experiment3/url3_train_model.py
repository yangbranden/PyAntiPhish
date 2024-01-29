#!/usr/bin/env python3

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics
import pandas as pd
import numpy as np
import pickle
import os

# CONSTANTS
iterations = 20
model_selector = 0

LR_max_iter = 3000
KNN_k_neighbors = 7
RF_n_estimators = 100

if model_selector == 0: # Logistic Regression
    model_name = "url3_model_LR.pickle"
elif model_selector == 1: # Support Vector Machine
    model_name = "url3_model_SVM.pickle"
elif model_selector == 2: # K-Nearest Neighbors
    model_name = "url3_model_KNN.pickle"
elif model_selector == 3: # Random Forest
    model_name = "url3_model_RF.pickle"

### IMPORT & PREPROCESS DATA ###
data = pd.read_csv("url3_data.csv", encoding='latin-1')

# For boolean values: False --> 0, True --> 1
data = data.replace({False: 0, True: 1})

# Define features (x) and labels (y)
if model_selector == 0: # Logistic Regression
    features = np.array(data[["netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "percent_count", "atsign_count", "hashsign_count", "plus_count", "comma_count", "has_bad_tld"]])
elif model_selector == 1: # Support Vector Machine
    features = np.array(data[["netloc_len_ratio", "pathcomp_len", "percent_count", "atsign_count", "hashsign_count", "plus_count", "comma_count", "has_bad_tld"]])
elif model_selector == 2: # K-Nearest Neighbors
    features = np.array(data[["subdomain_len", "pathcomp_len_ratio", "period_count", "dash_count", "atsign_count", "plus_count", "colon_count", "has_bad_tld", "has_tls"]])
elif model_selector == 3: # Random Forest
    features = np.array(data[["url_length", "subdomain_len", "subdomain_len_ratio", "netloc_len", "netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "period_count",
            "slash_count", "percent_count", "dash_count", "question_count", "atsign_count", "ampersand_count", "hashsign_count", "equal_count", "underscore_count", "plus_count", 
            "colon_count", "semicolon_count", "comma_count", "exclamation_count", "tilde_count", "dollar_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", 
            "has_tls", "typosquatting"]])
labels = np.array(data["result"])
# print(features)
# print(labels)

### DEFINE AND TRAIN MODEL ###
# Deterministic split; same split to test iterations against each other
x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)

# If already exists, check acc
if os.path.exists(model_name):
    saved_model = open(model_name, "rb")
    model = pickle.load(saved_model)
    best = model.score(x_test, y_test)
else:
    best = 0

for i in range(iterations):
    # Split data into new randomized training and testing sets
    x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.3)
    
    # Models tested: LogisticRegression, SVM, KNN, Random Forest
    if model_selector == 0:
        model = LogisticRegression(max_iter=LR_max_iter)
    elif model_selector == 1:
        model = LinearSVC(dual='auto')
    elif model_selector == 2:
        model = KNeighborsClassifier(n_neighbors=KNN_k_neighbors) # play around with k value
    elif model_selector == 3:
        model = RandomForestClassifier(n_estimators=RF_n_estimators) # play around with number of trees

    # Train model
    model.fit(x_train, y_train)

    acc = model.score(x_test, y_test)
    
    iter_update = f"Iteration {i}: {acc}"
    
    # Save best model
    if acc > best:
        iter_update += " (New best)"
        best = acc
        with open(model_name, "wb") as f:
            pickle.dump(model, f)
    
    print(iter_update)

### PRINT ACC OF ALL MODELS ###
print("\n### EXPERIMENT # ###\n\n")
for model_name in ["url3_model_LR.pickle", "url3_model_SVM.pickle", "url3_model_KNN.pickle", "url3_model_RF.pickle"]:
    if model_name == "url3_model_LR.pickle": # Logistic Regression
        features = np.array(data[["netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "percent_count", "atsign_count", "hashsign_count", "plus_count", 
            "comma_count", "has_bad_tld"]])
    elif model_name == "url3_model_SVM.pickle": # Support Vector Machine
        features = np.array(data[["netloc_len_ratio", "pathcomp_len", "percent_count", "atsign_count", "hashsign_count", "plus_count", "comma_count", "has_bad_tld"]])
    elif model_name == "url3_model_KNN.pickle": # K-Nearest Neighbors
        features = np.array(data[["subdomain_len", "pathcomp_len_ratio", "period_count", "dash_count", "atsign_count", "plus_count", "colon_count", "has_bad_tld", "has_tls"]])
    elif model_name == "url3_model_RF.pickle": # Random Forest
        features = np.array(data[["url_length", "subdomain_len", "subdomain_len_ratio", "netloc_len", "netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "period_count",
            "slash_count", "percent_count", "dash_count", "question_count", "atsign_count", "ampersand_count", "hashsign_count", "equal_count", "underscore_count", "plus_count", 
            "colon_count", "semicolon_count", "comma_count", "exclamation_count", "tilde_count", "dollar_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", 
            "has_tls", "typosquatting"]])
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
    print()