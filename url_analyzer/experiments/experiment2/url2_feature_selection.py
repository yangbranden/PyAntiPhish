#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2

data = pd.read_csv("../url_all_features.csv", encoding='latin-1')
data = data.drop(data.columns[0], axis=1) # ignore URL for feature selection process
X = data.iloc[:,0:29] # independent columns
y = data.iloc[:,-1] # target column

### 2 - Univariate Feature Selection (Chi-Square Test) ###
sel = SelectKBest(chi2, k='all')
fit = sel.fit(X,y)
dfscores = pd.DataFrame(fit.scores_)
dfcolumns = pd.DataFrame(X.columns)

# concat two dataframes for better visualization 
df = pd.concat([dfcolumns,dfscores],axis=1)
df.columns = ['Feature','Score']  # naming the dataframe columns
df = df.sort_values('Score', ascending=False)
display(df)

# Matplotlib visualization
fig, ax = plt.subplots()
ax.axis('off')
ax.set_title("Experiment 2 - Chi-Square Test", y=1.1, pad=10)
colors = [['w' for cell in row] for row in df.values]
for i in range(len(df.values)):
    if df.values[i][1] < 100.0:
        colors[i][1] = '#FF6961'
table = ax.table(cellText=df.values, cellColours=colors, loc='center', cellLoc='center', colLabels=df.columns)
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1, 0.9)
plt.show()