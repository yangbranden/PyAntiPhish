#!/usr/bin/env python3

import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from scipy.special import expit

# THIS SCRIPT IS TO CREATE GRAPHS/DIAGRAMS TO DEMONSTRATE HOW EACH CLASSIFIER WORKS
# WILL BE SHOWCASING THE URL_LENGTH FEATURE TO SHOW HOW EACH MODEL FUNCTIONS IN 2D

model_selector = 0

LR_max_iter = 3000
KNN_k_neighbors = 7
RF_n_estimators = 100

if model_selector == 0: # Logistic Regression
    model_name = "url0_model_LR.pickle"
elif model_selector == 1: # Support Vector Machine
    model_name = "url0_model_SVM.pickle"
elif model_selector == 2: # K-Nearest Neighbors
    model_name = "url0_model_KNN.pickle"
elif model_selector == 3: # Random Forest
    model_name = "url0_model_RF.pickle"
# Read the model from the pickle file
try:
    saved_model = open(model_name, "rb")
    model = pickle.load(saved_model)
except FileNotFoundError:
    print("Model not found.")
    exit()

data = pd.read_csv("url0_data.csv", encoding='latin-1')
data = data.drop(data.columns[0], axis=1)   # drop URL column
# data.loc[data["result"]=="phishing", "result"] = 1  # change result to be numerical
# data.loc[data["result"]=="benign", "result"] = 0    # change result to be numerical
x = data["url_length"]  # independent feature (we will use url_length to visualize)
y = data["result"]      # target column

features = np.array(data[["url_length", "subdomain_len", "subdomain_len_ratio", "netloc_len", "netloc_len_ratio", "pathcomp_len", "pathcomp_len_ratio", "period_count",
            "slash_count", "percent_count", "dash_count", "question_count", "atsign_count", "ampersand_count", "hashsign_count", "equal_count", "underscore_count", "plus_count", 
            "colon_count", "semicolon_count", "comma_count", "exclamation_count", "tilde_count", "dollar_count", "has_bad_tld", "has_bad_tld_location", "has_raw_ip", 
            "has_tls", "typosquatting"]])
labels = np.array(data["result"])
x_train, x_test, y_train, y_test = train_test_split(features, labels, test_size=0.3, random_state=42)

### 1 - LOGISTIC REGRESSION ###
if model_selector == 0:
    y_pred = model.predict(x_test)
    # y_pred_prob = model.predict_proba(x_test)[:,1]
    
    print("X_TEST:", x_test)
    print("Y_PRED:", y_pred)
    print("Y_TEST:", y_test)
    # sns.scatterplot(x=x_test[:,0], y=y_pred, hue=y_test)
    
    y = [{'phishing': 1, 'benign': 0}[item] for item in y]
    # y_test = [{'phishing': 1, 'benign': 0}[item] for item in y_test]
    wat = np.linspace(-20, 150)
    print(wat)
    sigmoid = expit(wat)
    plt.plot(sigmoid, c="green", label="LRcurve")
    
    # sns.regplot(x=x, y=y, data=data, logistic=True)
    
    ax = plt.gca()
    # ax.set_ylim([-0.1, 1.1])
    # ax.set_xlim([0, 400])
    # plt.legend(title="Actual")
    plt.xlabel('FEATURE')
    plt.ylabel('Predicted')
    plt.show()

### 2 - SUPPORT VECTOR MACHINE (LINEAR KERNEL) ###
elif model_selector == 1:
    model = SVC(kernel="linear")
    print()


### 3 - K-NEAREST NEIGHBORS ###
elif model_selector == 2:
    model = KNeighborsClassifier(n_neighbors=KNN_k_neighbors)
    print()


### 4 - RANDOM FOREST (this one is kinda hard to visualize) ###
elif model_selector == 3:
    model = RandomForestClassifier(n_estimators=RF_n_estimators)
    print()

