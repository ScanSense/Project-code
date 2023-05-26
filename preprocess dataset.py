import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Load the dataset
df = pd.read_csv('UNSW_NB15_training-set.csv')

# Remove the 'proto', 'service', 'state', and 'attack_cat' columns
df = df.drop(['proto', 'service', 'state', 'attack_cat'], axis=1)

# Encode the 'label' column as a categorical feature
le = LabelEncoder()
df['label'] = le.fit_transform(df['label'])

# Save the preprocessed dataset
df.to_csv('preprocessed_dataset.csv', index=False)
