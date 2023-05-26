import pandas as pd
from sklearn.preprocessing import MinMaxScaler

# load dataset
df = pd.read_csv('preprocessed_dataset.csv')

# normalize columns except the target column (assuming it is the last column)
scaler = MinMaxScaler()
df.iloc[:, :-1] = scaler.fit_transform(df.iloc[:, :-1])

# save normalized dataset to a new CSV file
df.to_csv('normalized_dataset.csv', index=False)
