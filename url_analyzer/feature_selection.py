import pandas as pd
import numpy as np
import seaborn as sns
from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import VarianceThreshold
from sklearn.feature_selection import chi2
from sklearn.ensemble import ExtraTreesClassifier
import matplotlib.pyplot as plt

data = pd.read_csv("url_data.csv", encoding='latin-1')
data = data.drop(data.columns[0], axis=1)
# print(data)
X = data.iloc[:,0:14]  # independent columns
y = data.iloc[:,-1]    # target column 
# print(X)
# print(y)

### 1 - Univariate Selection (SelectKBest with chi-squared test) ###
# apply SelectKBest class to rank features
bestfeatures = SelectKBest(score_func=chi2, k='all')
fit = bestfeatures.fit(X,y)
dfscores = pd.DataFrame(fit.scores_)
dfcolumns = pd.DataFrame(X.columns)
# concat two dataframes for better visualization 
featureScores = pd.concat([dfcolumns,dfscores],axis=1)
featureScores.columns = ['Features','Score']  # naming the dataframe columns
print(featureScores.nlargest(14,'Score'))
