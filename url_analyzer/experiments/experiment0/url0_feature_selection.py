#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display

data = pd.read_csv("../url_all_features.csv", encoding='latin-1')
data = data.drop(data.columns[0], axis=1) # ignore URL for feature selection process
X = data.iloc[:,0:29] # independent columns
y = data.iloc[:,-1] # target column

#################################### CHANGE BELOW FOR EACH EXPERIMENT ####################################

# i'm using this to visualize experiments 3 & 4 lol

# Create list to display in table
output = [["Feature", "Always selected by Forward-SFS"]]
output.append([data.columns[0], 0])
output.append([data.columns[1], 1])
output.append([data.columns[2], 1])
output.append([data.columns[3], 0])
output.append([data.columns[4], 0])
output.append([data.columns[5], 0])
output.append([data.columns[6], 0])
output.append([data.columns[7], 1])
output.append([data.columns[8], 1])
output.append([data.columns[9], 0])
output.append([data.columns[10], 1]) # dash
output.append([data.columns[11], 0])
output.append([data.columns[12], 0])
output.append([data.columns[13], 0])
output.append([data.columns[14], 0])
output.append([data.columns[15], 0])
output.append([data.columns[16], 0])
output.append([data.columns[17], 0])
output.append([data.columns[18], 1])
output.append([data.columns[19], 0])
output.append([data.columns[20], 0])
output.append([data.columns[21], 0])
output.append([data.columns[22], 0])
output.append([data.columns[23], 0])
output.append([data.columns[24], 1])
output.append([data.columns[25], 0])
output.append([data.columns[26], 0])
output.append([data.columns[27], 0])
output.append([data.columns[28], 0])

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