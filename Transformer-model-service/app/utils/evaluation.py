import torch
import torch.nn as nn
import pandas as pd
from logging import error, info

# =============================
# Evaluation Function
# =============================
def eval_model(
    model,
    eval_loader,
    criterion,
    device='cpu'
):
    """Execute the evaluation loop and return evaluation loss."""
    model.eval()
    model.to(device)
    eval_loss = 0.0

    # Disable gradient computation during evaluation
    with torch.no_grad():            
        for batch_idx, (batch_features, batch_labels) in enumerate(eval_loader):
            batch_features = [tensor.to(device) for tensor in batch_features]
            batch_labels = [tensor.to(device) for tensor in batch_labels] 
            
            outputs = model(batch_features)
            loss = criterion(outputs, batch_labels)

            # Get predictions, using the argmax over the logits dimension
            predictions = torch.argmax(outputs, dim=1)

            # Calculate correct predictions (optionally, filter out ignore_index if necessary)
            # If your labels contain the ignore index (-1), then you need extra filtering.
            correct_predictions = (predictions == batch_labels).sum().item()
            total_predictions = batch_labels.size(0)
            wrong_predictions = total_predictions - correct_predictions

            # Print detailed results per batch
            accuracy = (correct_predictions / total_predictions) * 100 if total_predictions > 0 else 0
            print(f"Evaluating Batch {batch_idx+1}/{len(eval_loader)}")
            print(f"   Loss: {loss.item():.4f}")
            print(f"   Correct: {correct_predictions}/{total_predictions}")
            print(f"   Wrong:   {wrong_predictions}/{total_predictions}")
            print(f"   Batch Accuracy: {accuracy:.2f}%\n")

            # Aggregate the loss weighted by batch size
            eval_loss += loss.item() * batch_features.size(0)
            print(f"Evaluating Batch {batch_idx+1}/{len(eval_loader)} - Loss: {loss.item():.4f}")

    # Compute the average loss over all examples
    avg_loss = eval_loss / len(eval_loader.dataset)
    print(f"Evaluation complete - Average Loss: {avg_loss:.4f}\n")

    return avg_loss