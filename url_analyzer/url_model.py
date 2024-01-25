#!/usr/bin/python3

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics
import pandas as pd
import numpy as np
import pickle
import os

# CONSTANTS
train = True
iterations = 1
model_selector = 0

LR_max_iter = 3000
KNN_n_neighbors = 11
RF_n_estimators = 100

if model_selector == 0: # Logistic Regression
    model_name = "url_model_LR.pickle"
elif model_selector == 1: # SVM
    model_name = "url_model_SVM.pickle"
elif model_selector == 2: # KNN
    model_name = "url_model_KNN.pickle"
elif model_selector == 3: # Random Forest
    model_name = "url_model_RF.pickle"

### IMPORT & PREPROCESS DATA ###
data = pd.read_csv("url_data.csv", encoding='latin')

# False --> 0, True --> 1
data = data.replace({False: 0, True: 1})
# data = data.replace({"benign": 0, "phishing": 1})
# print(data)

# Define features (x) and labels (y)
features = np.array(data[["url_length", "subdomain_len_ratio", "pathcomp_len_ratio", "period_count", "percent_count", "dash_count", "atsign_count", 
                "ampersand_count", "equal_count", "hashsign_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", "has_tls", "typosquatting"]])
labels = np.array(data["result"])
test = np.array(data)
# print(features)
# print(labels)

### DEFINE AND TRAIN MODEL ###
# Deterministic split
x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)
# print(x_test)

# If already exists, check acc
if os.path.exists(model_name):
    saved_model = open(model_name, "rb")
    model = pickle.load(saved_model)
    best = model.score(x_test, y_test)
else:
    best = 0

if train:
    for i in range(iterations):
        # Split data into new randomized training and testing sets
        x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.3)
        
        # Models tested: LogisticRegression, SVM, KNN, Random Forest
        if model_selector == 0:
            model = LogisticRegression(max_iter=LR_max_iter)
        elif model_selector == 1:
            model = SVC(kernel="linear")
        elif model_selector == 2:
            model = KNeighborsClassifier(n_neighbors=KNN_n_neighbors) # play around with k value
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
else:
    saved_model = open(model_name, "rb")
    model = pickle.load(saved_model)

### USE MODEL (PREDICT) ###
predictions = model.predict(x_test)
for i in range(len(predictions)):
    print(f"Predicted: {predictions[i]:8} | Actual: {y_test[i]:8} | Data: {x_test[i]}")
print(model.score(x_test, y_test))
print(metrics.accuracy_score(y_test, predictions))

### PRINT ACC OF ALL MODELS ###
x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)
print("Printing current acc of all models")
for model_name in ["url_model_LR.pickle", "url_model_SVM.pickle", "url_model_KNN.pickle", "url_model_RF.pickle"]:
    saved_model = open(model_name, "rb")
    model = pickle.load(saved_model)
    predictions = model.predict(x_test)
    print(model_name)
    print(model.score(x_test, y_test))
    print(metrics.accuracy_score(y_test, predictions))