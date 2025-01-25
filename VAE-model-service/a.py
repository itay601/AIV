import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from transformers import BertTokenizer, BertModel

# --------------------
# 1. Data Preprocessing
# --------------------
# Load data
data = pd.read_csv("packet_data.csv")



# Handle categorical features
cat_cols = ['Layer2_DataLink_EthernetType', 'Layer3_Network_Protocol']
le = LabelEncoder()
for col in cat_cols:
    data[col] = le.fit_transform(data[col])

# Handle TCP flags (convert to numerical)
tcp_flag_mapping = {'ACK': 16, 'SYN': 2, 'FIN': 1, 'RST': 4, 'PSH': 8, 'URG': 32}
data['Layer4_Transport_TCPFlags'] = data['Layer4_Transport_TCPFlags'].map(tcp_flag_mapping).fillna(0)

# Fill NaNs
data = data.fillna(0)

# Normalize numerical features
numerical_cols = [
    'Layer3_Network_TimeToLive', 'Layer4_Transport_SourcePort',
    'Layer4_Transport_DestinationPort', 'Payload_Length', 'Packet_Length'
]
scaler = StandardScaler()
data[numerical_cols] = scaler.fit_transform(data[numerical_cols])

# Load pre-trained BERT model and tokenizer
try:
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    bert_model = BertModel.from_pretrained('bert-base-uncased')
except Exception as e:
    print(f"Error loading BERT model or tokenizer: {e}")
    exit()

def bert_encode(texts):
    # Tokenize and encode texts
    encoded = tokenizer(texts.tolist(), padding=True, truncation=True, return_tensors='pt')
    
    # Generate embeddings
    with torch.no_grad():
        outputs = bert_model(**encoded)
    
    # Use last hidden state as numeric representation
    return outputs.last_hidden_state.mean(dim=1)

# Generate BERT embeddings for string columns
string_cols = data.select_dtypes(include=['object']).columns
string_embeddings = []

for col in string_cols:
    print(f"Processing column: {col}")
    embeddings = bert_encode(data[col].astype(str))  # Ensure all text inputs are strings
    string_embeddings.append(embeddings)

# Concatenate BERT embeddings with numerical data
if string_embeddings:
    string_embeddings_tensor = torch.cat(string_embeddings, dim=1)
    numerical_data_tensor = torch.tensor(data.drop(columns=string_cols).values, dtype=torch.float32)
    full_data_tensor = torch.cat([numerical_data_tensor, string_embeddings_tensor], dim=1)
else:
    full_data_tensor = torch.tensor(data.values, dtype=torch.float32)

# Filter normal data (update this with your filtering criteria)
normal_data = full_data_tensor.numpy()

# --------------------
# 2. AutoEncoder Model
# --------------------
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(16, 8),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(16, input_dim)
        )
        
    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)
        return x

# Initialize model
input_dim = full_data_tensor.shape[1]
autoencoder = Autoencoder(input_dim)
print(f"Model architecture:\n{autoencoder}")

# --------------------
# 3. Data Preparation
# --------------------
# Train-test split
X_train, X_val = train_test_split(normal_data, test_size=0.2, random_state=42)

# Convert to DataLoader
train_dataset = TensorDataset(torch.FloatTensor(X_train), torch.FloatTensor(X_train))
val_dataset = TensorDataset(torch.FloatTensor(X_val), torch.FloatTensor(X_val))

batch_size = 32
train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=batch_size)

# --------------------
# 4. Training Setup
# --------------------
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
autoencoder = autoencoder.to(device)
criterion = nn.MSELoss()
optimizer = optim.Adam(autoencoder.parameters(), lr=0.001, weight_decay=1e-4)
scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5)

# --------------------
# 5. Training Loop
# --------------------
num_epochs = 200
best_loss = float('inf')
patience = 10
patience_counter = 0

train_losses = []
val_losses = []

for epoch in range(num_epochs):
    # Training
    autoencoder.train()
    train_loss = 0
    for batch in train_loader:
        inputs, _ = batch
        inputs = inputs.to(device)
        
        optimizer.zero_grad()
        outputs = autoencoder(inputs)
        loss = criterion(outputs, inputs)
        loss.backward()
        optimizer.step()
        
        train_loss += loss.item() * inputs.size(0)
    
    # Validation
    autoencoder.eval()
    val_loss = 0
    with torch.no_grad():
        for batch in val_loader:
            inputs, _ = batch
            inputs = inputs.to(device)
            
            outputs = autoencoder(inputs)
            loss = criterion(outputs, inputs)
            val_loss += loss.item() * inputs.size(0)
    
    # Calculate epoch losses
    train_loss = train_loss / len(train_loader.dataset)
    val_loss = val_loss / len(val_loader.dataset)
    
    # Learning rate scheduling
    scheduler.step(val_loss)
    
    # Early stopping
    if val_loss < best_loss:
        best_loss = val_loss
        patience_counter = 0
        # Save best model
        torch.save(autoencoder.state_dict(), "best_autoencoder.pth")
    else:
        patience_counter += 1
    
    # Store losses for plotting
    train_losses.append(train_loss)
    val_losses.append(val_loss)
    
    print(f'Epoch {epoch+1}/{num_epochs} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f}')
    
    if patience_counter >= patience:
        print("Early stopping triggered")
        break