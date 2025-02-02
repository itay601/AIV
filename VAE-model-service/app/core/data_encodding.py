import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.feature_extraction.text import CountVectorizer
from core.ae_model import AutoEncoder
from core.data_processing import PreProcessingData
import torch
from torch.serialization import safe_globals
from gensim.models.word2vec import Word2Vec



def load_model(checkpoint_path='autoencoder_checkpoint.pth'):
    """
    Load the saved AutoEncoder model

    Args:
        checkpoint_path: Path to the saved model checkpoint

    Returns:
        Loaded AutoEncoder model
    """
    checkpoint = torch.load(checkpoint_path , weights_only=False)
    input_dim = checkpoint['model_architecture']['input_dim']

    model = AutoEncoder(input_dim)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    return model

def load_word2vec():
    with safe_globals([Word2Vec]):
        model = torch.load("./word2vec_model.pth",weights_only=True)
    return model

class NetworkDataProcessor:
    def __init__(self, vector_size=100):
        self.label_encoder = LabelEncoder()
        self.min_max_scaler = MinMaxScaler()
        self.word2vec_model = load_word2vec()
        self.vector_size = vector_size
        self.vectorizer = CountVectorizer(token_pattern=r'\b\w+\b')

    def _preprocess_text(self, text_series):
        """Preprocess text columns"""
        return text_series.fillna('UNKNOWN').astype(str)

    def _encode_categorical(self, series):
        """Encode categorical data"""
        return self.label_encoder.fit_transform(self._preprocess_text(series))

    def _scale_numeric(self, series):
        """Scale numeric data"""
        return self.min_max_scaler.fit_transform(series.values.reshape(-1, 1)).flatten()

    def _create_word2vec_model(self, corpus):
        """Create Word2Vec model"""
        tokenized_corpus = [str(text).split() for text in corpus]
        self.word2vec_model = Word2Vec(
            sentences=tokenized_corpus,
            vector_size=self.vector_size,
            window=5,
            min_count=1,
            workers=4
        )

    def _text_to_embedding(self, text_series):
        """Convert text to embeddings"""
        if self.word2vec_model is None:
            raise ValueError("Word2Vec model not initialized")

        embeddings = []
        for text in text_series:
            words = str(text).split()
            word_vecs = [self.word2vec_model.wv[word] for word in words if word in self.word2vec_model.wv]
            embedding = np.mean(word_vecs, axis=0) if word_vecs else np.zeros(self.vector_size)
            embeddings.append(embedding)

        return np.array(embeddings)

    def process_dataframe(self, df):
        """Process entire DataFrame"""
        processed_df = df.copy()

        # Text columns for embedding
        text_columns = [
            'Layer2_DataLink_SourceMAC', 'Layer2_DataLink_DestinationMAC',
            'Layer3_Network_SourceIP', 'Layer3_Network_DestinationIP',
            'Layer3_Network_Protocol', 'Payload_ASCII', 'Payload_Hex'
            ,'Packet_Timestamp'
        ]

        # Create corpus for Word2Vec
        #corpus = processed_df[text_columns].apply(lambda row: ' '.join(row.astype(str)), axis=1)
        #self._create_word2vec_model(corpus)

        for col in processed_df.columns:
            if df[col].dtype == 'object':
                # Embedded text columns
                if col in text_columns:
                    processed_df[col] = self._text_to_embedding(df[col])
                # Other categorical columns
                else:
                    processed_df[col] = self._encode_categorical(df[col])

            # Numeric columns
            elif np.issubdtype(df[col].dtype, np.number):
                processed_df[col] = self._scale_numeric(df[col])

        return processed_df

# Usage
def process_network_data(packets):
    df = packets.copy()
    df = PreProcessingData(df)
    processor = NetworkDataProcessor()
    processed_df = processor.process_dataframe(df)
    return processed_df