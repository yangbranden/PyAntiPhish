#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
from IPython.display import display

data = pd.read_csv("../url_all_features.csv", encoding='latin-1')
data = data.drop(data.columns[0], axis=1) # ignore URL for feature selection process
X = data.iloc[:,0:29] # independent columns
y = data.iloc[:,-1] # target column

#################################### CHANGE BELOW FOR EACH EXPERIMENT ####################################

print(X.columns)

# i'm using this to visualize experiments 3 & 4 lol
## EXPERIMENT 3 ##
#            1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9
exp3_RF_1 = [0,1,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,1,0,0,0,0,0,1,0,0,1,0]
exp3_RF_2 = [1,1,1,0,0,0,1,1,1,0,1,0,0,0,0,1,0,0,1,0,0,0,0,0,1,1,0,1,0]
exp3_RF_3 = [0,1,1,1,0,1,0,1,1,1,1,1,0,0,0,1,0,0,1,0,0,0,0,0,1,0,0,1,0]
exp3_RF_4 = [0,1,1,1,0,1,1,1,1,0,1,1,0,0,0,1,0,0,1,0,0,0,0,0,1,0,0,1,0]
exp3_RF_5 = [0,1,1,1,0,1,0,1,1,1,1,0,1,0,0,1,0,0,1,0,0,0,0,0,1,0,0,1,0]
exp3_RF_6 = [0,1,1,1,0,1,1,1,1,0,1,0,0,0,1,1,0,0,1,0,0,0,0,0,1,0,0,1,0]
exp3_RF_7 = [1,1,1,1,0,0,1,1,1,0,1,0,1,0,0,1,0,0,1,0,0,0,0,0,1,1,0,1,0]
exp3_RF_8 = [0,1,1,1,1,1,0,1,1,1,1,0,1,0,0,1,0,0,1,0,0,0,0,0,1,0,0,1,0]
exp3_RF_9 = [1,1,1,1,1,0,0,1,1,0,1,0,0,0,0,1,0,0,1,0,0,0,1,0,1,1,0,1,0]
exp3_RF_0 = [0,1,1,1,1,1,0,1,1,1,1,0,0,0,1,1,0,0,1,0,0,0,0,0,1,0,0,1,0]

## EXPERIMENT 4 ##
exp4_RF_1 = [1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
exp4_RF_2 = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1]
exp4_RF_3 = [1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1]
exp4_RF_4 = [1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1]
exp4_RF_5 = [0,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1]
exp4_RF_6 = [0,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1]
exp4_RF_7 = [1,1,1,1,1,0,0,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]
exp4_RF_8 = [1,1,1,1,1,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1]
exp4_RF_9 = [0,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,0]
exp4_RF_0 = [1,1,1,1,0,0,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1]


# Create list to display in table
output = [["Feature", "# Times Selected by Forward-SFS"]]
for i in range(len(X.columns)):
    output.append([X.columns[i], 0])

for i in range(len(output)):
    if i == 0: # skip header
        continue
    output[i][1] += exp3_RF_1[i-1]
    output[i][1] += exp3_RF_2[i-1]
    output[i][1] += exp3_RF_3[i-1]
    output[i][1] += exp3_RF_4[i-1]
    output[i][1] += exp3_RF_5[i-1]
    output[i][1] += exp3_RF_6[i-1]
    output[i][1] += exp3_RF_7[i-1]
    output[i][1] += exp3_RF_8[i-1]
    output[i][1] += exp3_RF_9[i-1]
    output[i][1] += exp3_RF_0[i-1]

df = pd.DataFrame(output)
display(df)

# Matplotlib visualization
fig, ax = plt.subplots()
ax.axis('off')
ax.set_title("Experiment 3 - Forward-SFS for Random Forest", y=1.1, pad=10)
colors = [['#FF6961' if (isinstance(cell, int) and cell <= 4) else 'w' for cell in row] for row in output]
table = ax.table(cellText=output, cellColours=colors, loc='center', cellLoc='center', colLabels=None)
table.auto_set_font_size(False)
table.set_fontsize(10)
table.scale(1, 0.9)
plt.show()