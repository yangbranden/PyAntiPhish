#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SequentialFeatureSelector

model_selector = 3

LR_max_iter = 3000
KNN_k_neighbors = 7
RF_n_estimators = 100

data = pd.read_csv("../url_all_features.csv", encoding='latin-1')
data = data.drop(data.columns[0], axis=1) # ignore URL for feature selection process
X = data.iloc[:,0:29] # independent columns
y = data.iloc[:,-1] # target column

### 4 - Backward-SequentialFeatureSelector for each model ###
if model_selector == 0:
    model = LogisticRegression(max_iter=LR_max_iter, verbose=1)
    title = "Experiment 4 - Backward-SFS for Logistic Regression"
elif model_selector == 1:
    model = LinearSVC(dual='auto', verbose=1)
    title = "Experiment 4 - Backward-SFS for Support Vector Machine"
elif model_selector == 2:
    model = KNeighborsClassifier(n_neighbors=KNN_k_neighbors) # play around with k value
    title = "Experiment 4 - Backward-SFS for K-Nearest Neighbors"
elif model_selector == 3:
    model = RandomForestClassifier(n_estimators=RF_n_estimators, verbose=1) # play around with number of trees
    title = "Experiment 4 - Backward-SFS for Random Forest"
sel = SequentialFeatureSelector(model, n_features_to_select='auto', scoring='accuracy', direction='backward', tol=0.0001)
sel.fit(X,y)
selected_features = sel.get_support()

# Create list to display in table
output = [["Feature", "Selected by Backward-SFS"]]
for i in range(len(selected_features)):
    output.append([data.columns[i], selected_features[i]])

df = pd.DataFrame(output)
display(df)

# Matplotlib visualization
fig, ax = plt.subplots()
ax.axis('off')
ax.set_title(title, y=1.1, pad=10)
colors = [['#FF6961' if cell == False else 'w' for cell in row] for row in output]
table = ax.table(cellText=output, cellColours=colors, loc='center', cellLoc='center', colLabels=None)
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1, 0.9)
plt.show()