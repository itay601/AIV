import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder , MinMaxScaler, OneHotEncoder
import numpy as np
from gensim.models import Word2Vec
from collections.abc import Sequence
from sklearn.feature_extraction.text import CountVectorizer



def load_data(file_path : str) -> pd.DataFrame:
    df = pd.read_csv(file_path)
    return df


critical_columns = [
        
        
    ]


# 1. Handle missing values (preserve all features)
# Fill numerical missing values with 0
def PreProcessingData(df : pd.DataFrame) -> pd.DataFrame:
    num_cols = df.select_dtypes(include=['int64', 'float64']).columns
    df[num_cols] = df[num_cols].fillna(0)
    # Remove rows with missing critical information
    cleaned_df = df.dropna(subset=critical_columns)
    # Optional: Log removed packets for analysis
    print(f"Original dataset size: {len(df)}")
    print(f"Cleaned dataset size: {len(cleaned_df)}")
    print(f"Packets removed: {len(df) - len(cleaned_df)}")
    return cleaned_df
