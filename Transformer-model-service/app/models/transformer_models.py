import math
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import ast
import json


# 1.1 Positional Encoding (Sinusoidal)
class PositionalEncoding(nn.Module):
    def __init__(self, d_model, max_len=5000, dropout=0.1):
        super(PositionalEncoding, self).__init__()
        self.dropout = nn.Dropout(p=dropout)
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float32).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * -(math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        if d_model % 2 == 1:
            pe[:, 1::2] = torch.cos(position * div_term[: (d_model // 2)])
        else:
            pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # shape: (1, max_len, d_model)
        self.register_buffer('pe', pe)

    def forward(self, x):
        """
        x: Tensor, shape (batch_size, seq_length, d_model)
        """
        # Convert list to tensor if x is a list
        if isinstance(x, list):
            x = torch.tensor(x, dtype=torch.float32)
        x = x + self.pe[:, :x.size(1)]
        return self.dropout(x)

# 1.2 Transformer Encoder Block (with Pre-Normalization)
class TransformerEncoderBlock(nn.Module):
    def __init__(self, d_model, nhead, dropout=0.1, dim_feedforward=2048):
        super(TransformerEncoderBlock, self).__init__()
        # Pre-normalization scheme
        self.self_attn = nn.MultiheadAttention(d_model, nhead, dropout=dropout)
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.dropout1 = nn.Dropout(dropout)
        self.dropout2 = nn.Dropout(dropout)
        self.feedforward = nn.Sequential(
            nn.Linear(d_model, dim_feedforward),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(dim_feedforward, d_model),
            nn.Dropout(dropout)
        )

    def forward(self, src, src_mask=None, src_key_padding_mask=None):
        # Pre-norm and residual connection for self-attention sub-layer
        src2, _ = self.self_attn(self.norm1(src), self.norm1(src), self.norm1(src),
                                   attn_mask=src_mask, key_padding_mask=src_key_padding_mask)
        src = src + self.dropout1(src2)
        # Pre-norm and residual for feedforward sub-layer
        src2 = self.feedforward(self.norm2(src))
        src = src + self.dropout2(src2)
        return src

# 1.3 Multi-Head Latent Attention Module
class MultiHeadLatentAttention(nn.Module):
    def __init__(self, d_model, nhead, num_latents=4, dropout=0.1):
        """
        num_latents defines the number of learnable latent vectors that will attend to the sequence.
        """
        super(MultiHeadLatentAttention, self).__init__()
        self.num_latents = num_latents
        self.latents = nn.Parameter(torch.randn(num_latents, d_model))
        self.attn = nn.MultiheadAttention(d_model, nhead, dropout=dropout)
        self.layernorm = nn.LayerNorm(d_model)

    def forward(self, x, attn_mask=None, key_padding_mask=None):
        """
        x: Tensor, shape (seq_length, batch_size, d_model)
        Returns a latent summary tensor: (num_latents, batch_size, d_model)
        """
        batch_size = x.size(1)
        latent_queries = self.latents.unsqueeze(1).expand(-1, batch_size, -1)
        latent_out, _ = self.attn(latent_queries, x, x, attn_mask=attn_mask,
                                  key_padding_mask=key_padding_mask)
        latent_out = self.layernorm(latent_out)
        return latent_out

# 1.4 Mixture of Experts (MOE)
class MoE(nn.Module):
    def __init__(self, input_dim, expert_hidden_dim, num_experts=4, output_dim=None):
        super(MoE, self).__init__()
        self.num_experts = num_experts
        out_dim = output_dim if output_dim is not None else input_dim
        self.experts = nn.ModuleList([
            nn.Sequential(
                nn.Linear(input_dim, expert_hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.1),  # Additional dropout inside experts
                nn.Linear(expert_hidden_dim, out_dim)
            ) for _ in range(num_experts)
        ])
        self.gate = nn.Linear(input_dim, num_experts)
        self.norm = nn.LayerNorm(input_dim)  # Regularization for gating

    def forward(self, x):
        """
        x: Tensor, shape (batch_size, input_dim)
        """
        gate_input = self.norm(x)
        gate_scores = self.gate(gate_input)  # (batch_size, num_experts)
        weights = F.softmax(gate_scores, dim=-1)

        expert_outputs = []
        for expert in self.experts:
            expert_outputs.append(expert(x).unsqueeze(-1))  # (batch_size, output_dim, 1)
        expert_outputs = torch.cat(expert_outputs, dim=-1)  # (batch_size, output_dim, num_experts)
        weights = weights.unsqueeze(1)  # (batch_size, 1, num_experts)
        out = torch.bmm(expert_outputs, weights.transpose(1, 2)).squeeze(-1)
        return out

# 1.5 Enhanced MalwareClassifier Putting Everything Together
class MalwareClassifier(nn.Module):
    def __init__(self, d_model=128, nhead=4, num_encoder_layers=3,
                 num_latents=4, moe_hidden_dim=256, num_experts=4, num_classes=2, dropout=0.1):
        super(MalwareClassifier, self).__init__()
        # Positional encoding and input projection
        self.positional_encoding = PositionalEncoding(d_model, dropout=dropout)
        # Convolution for local feature extraction
        self.input_conv = nn.Conv1d(in_channels=d_model, out_channels=d_model,
                                    kernel_size=3, padding=1)

        # Transformer encoder layers with pre-normalization
        self.encoder_layers = nn.ModuleList([
            TransformerEncoderBlock(d_model, nhead, dropout=dropout) for _ in range(num_encoder_layers)
        ])

        # Latent attention module
        self.latent_attention = MultiHeadLatentAttention(d_model, nhead,
                                                         num_latents=num_latents, dropout=dropout)

        # Additional attention pooling branch for improved summary
        self.attn_pool = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.Tanh(),
            nn.Linear(d_model, 1)
        )

        # Mixture of Experts module
        # If merging two representations (e.g., mean pooling and attention pooling),
        # then input dimension becomes 2*d_model.
        self.moe = MoE(input_dim=2*d_model, expert_hidden_dim=moe_hidden_dim,
                       num_experts=num_experts, output_dim=d_model)

        # Classifier network
        self.classifier = nn.Sequential(
            nn.Linear(d_model, d_model // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(d_model // 2, num_classes)
        )

    def forward(self, x, src_mask=None, src_key_padding_mask=None):
        """
        x: Tensor of shape (batch_size, seq_length, d_model)
        """
        # Apply positional encoding
        x = self.positional_encoding(x)  # (batch_size, seq_length, d_model)

        # Apply local feature extraction using convolution
        # Permute to (batch_size, d_model, seq_length) for Conv1d
        x_conv = self.input_conv(x.transpose(1, 2))
        # Permute back to (batch_size, seq_length, d_model)
        x_conv = x_conv.transpose(1, 2)
        # Add residual connection from conv to original
        x = x + x_conv

        # Transformer expects (seq_length, batch_size, d_model)
        x = x.transpose(0, 1)
        for layer in self.encoder_layers:
            x = layer(x, src_mask=src_mask, src_key_padding_mask=src_key_padding_mask)

        # Obtain latent tokens using latent attention module; shape: (num_latents, batch_size, d_model)
        latent_tokens = self.latent_attention(x, attn_mask=src_mask, key_padding_mask=src_key_padding_mask)
        # Compute mean pooling over the latent tokens
        latent_summary_mean = latent_tokens.mean(dim=0)  # (batch_size, d_model)

        # Also perform attention pooling on all transformer tokens (for a richer summary)
        # Permute x back to (batch_size, seq_length, d_model)
        x_tokens = x.transpose(0, 1)
        attn_weights = self.attn_pool(x_tokens)  # (batch_size, seq_length, 1)
        attn_weights = F.softmax(attn_weights, dim=1)
        latent_summary_attn = torch.sum(attn_weights * x_tokens, dim=1)  # (batch_size, d_model)

        # Concatenate both pooled representations
        latent_summary = torch.cat([latent_summary_mean, latent_summary_attn], dim=-1)  # (batch_size, 2*d_model)

        # Pass combined latent summary through MOE
        moe_out = self.moe(latent_summary)  # (batch_size, d_model)

        # Final classification
        logits = self.classifier(moe_out)
        return logits


def initialize_model(
    d_model=128,
    nhead=4,
    num_encoder_layers=3,
    num_latents=4,
    moe_hidden_dim=256,
    num_experts=4,
    num_classes=2,
    dropout=0.1
):
    """Initialize and return the MalwareClassifier model."""
    return MalwareClassifier(
        d_model=d_model,
        nhead=nhead,
        num_encoder_layers=num_encoder_layers,
        num_latents=num_latents,
        moe_hidden_dim=moe_hidden_dim,
        num_experts=num_experts,
        num_classes=num_classes,
        dropout=dropout
    )


def setup_optimizer(model, learning_rate, l2_lambda):
    """Configure optimizer and scheduler."""
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, weight_decay=l2_lambda)
    scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)
    return optimizer, scheduler