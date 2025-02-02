import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset






class AutoEncoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.1),
            nn.Dropout(0.2),

            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.1),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),

            nn.Linear(32, 16),
            nn.BatchNorm1d(16),
            nn.LeakyReLU(0.1),

            nn.Linear(16, 8)
        )

        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.BatchNorm1d(16),
            nn.LeakyReLU(0.1),

            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),

            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.1),

            nn.Linear(64, 128),
            nn.BatchNorm1d(128),
            nn.LeakyReLU(0.1),

            nn.Linear(128, input_dim)  # Output layer
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded




def create_loader(data_array, batch_size=64):
    """Create dataloader with memory mapping"""
    # Convert DataFrame to NumPy array if necessary
    if isinstance(data_array, pd.DataFrame):
        data_array = data_array.to_numpy()  # Convert to NumPy array

    # Ensure data_array is 2D (num_samples, num_features)
    if len(data_array.shape) != 2:
        raise ValueError(f"Expected 2D array, but got shape {data_array.shape}")

    tensor = torch.tensor(data_array, dtype=torch.float32)
    return DataLoader(TensorDataset(tensor, tensor),
                      batch_size=batch_size,
                      pin_memory=True,
                      shuffle=True)