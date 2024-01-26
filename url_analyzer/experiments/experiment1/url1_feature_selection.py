#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display
from sklearn.feature_selection import VarianceThreshold

data = pd.read_csv("../url_all_features.csv", encoding='latin-1')
data = data.drop(data.columns[0], axis=1) # ignore URL for feature selection process
X = data.iloc[:,0:29] # independent columns
y = data.iloc[:,-1] # target column

### 1 - Variance Threshold of 95% ###
sel = VarianceThreshold(threshold=0.05)
sel.fit(X)
should_remove = sel.get_support()

# Create list to display in table
output = [["Feature", "Variance greater than 5%"]]
for i in range(len(should_remove)):
    output.append([data.columns[i], should_remove[i]])

df = pd.DataFrame(output)
display(df)

# Matplotlib visualization
fig, ax = plt.subplots()
ax.axis('off')
colors = [['#FF6961' if cell == False else 'w' for cell in row] for row in output]
table = ax.table(cellText=output, cellColours=colors, loc='center', cellLoc='center', colLabels=None)
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1, 0.9)
plt.show()