#!/usr/bin/env python3

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def ecdf(data):
    """Compute ECDF for a one-dimensional array of measurements."""
    n = len(data)
    x = np.sort(data)
    y = np.arange(1, n + 1) / n
    return x, y

# Read data from CSV file
data_df = pd.read_csv('url_data.csv', encoding='latin-1')

# Extract the column containing the data
data_column = 'subdomain_len'
data = data_df[data_column].values

# Compute ECDF
x, y = ecdf(data)

# Plot ECDF
plt.figure(figsize=(8, 6))
plt.plot(x, y, marker='.', linestyle='none')
plt.xlabel('Data')
plt.ylabel('ECDF')
plt.title('Empirical Cumulative Distribution Function (ECDF)')
plt.grid(True)
plt.show()