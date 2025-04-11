import torch
import torch.nn as nn
import pandas as pd
from logging import error, info


#logger = logging.info()
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
    malware_count = 0
    # Disable gradient computation during evaluation
    with torch.no_grad():
        for batch_idx, batch_data in enumerate(eval_loader):
            
            # Handle different types of dataloader outputs
            if isinstance(batch_data, (list, tuple)) and len(batch_data) == 2:
                batch_features, batch_labels = batch_data
            else:
                print(f"Unexpected dataloader output format: {type(batch_data)}")
                continue
            
            # Print detailed information about what we received
            print(f"Type of batch_features: {type(batch_features)}")
            if isinstance(batch_features, list):
                print(f"First element type: {type(batch_features[0]) if batch_features else 'Empty list'}")
                if batch_features and isinstance(batch_features[0], (list, tuple)):
                    print(f"First sub-element type: {type(batch_features[0][0]) if batch_features[0] else 'Empty sublist'}")
            
            # Handle different types of feature data
            if isinstance(batch_features, torch.Tensor):
                # Already a tensor, just move to device
                batch_features = batch_features.to(device)
            elif isinstance(batch_features, list):
                # Try to determine if we have a list of tensors or a list of lists
                if batch_features and isinstance(batch_features[0], torch.Tensor):
                    # Stack list of tensors
                    batch_features = torch.stack(batch_features).to(device)
                elif batch_features and isinstance(batch_features[0], (list, tuple)):
                    # Convert nested list to tensor
                    try:
                        # Try to convert to a tensor directly
                        batch_features = torch.tensor([item for item in batch_features], dtype=torch.float32).to(device)
                    except ValueError:
                        # If that fails, try to process each sublist separately
                        tensors = []
                        for item in batch_features:
                            if isinstance(item, (list, tuple)):
                                tensors.append(torch.tensor(item, dtype=torch.float32))
                            elif isinstance(item, torch.Tensor):
                                tensors.append(item)
                        if tensors:
                            batch_features = torch.stack(tensors).to(device)
                        else:
                            print("Could not convert batch_features to tensor")
                            continue
                else:
                    # Simple list of values
                    try:
                        batch_features = torch.tensor(batch_features, dtype=torch.float32).to(device)
                    except ValueError as e:
                        print(f"Error converting batch_features to tensor: {e}")
                        continue
            else:
                print(f"Unsupported type for batch_features: {type(batch_features)}")
                continue
                
            # Similar handling for batch_labels
            if isinstance(batch_labels, torch.Tensor):
                batch_labels = batch_labels.to(device)
            elif isinstance(batch_labels, list):
                try:
                    batch_labels = torch.tensor(batch_labels, dtype=torch.long).to(device)
                except ValueError as e:
                    print(f"Error converting batch_labels to tensor: {e}")
                    continue
            else:
                print(f"Unsupported type for batch_labels: {type(batch_labels)}")
                continue



            # Move data to the device
            '''batch_features = batch_features.to(model.device)
            batch_labels = batch_labels.to(model.device)'''

            outputs = model(batch_features)
            loss = criterion(outputs, batch_labels)

            # Get predictions, using the argmax over the logits dimension
            predictions = torch.argmax(outputs, dim=1)

            # Count malware predictions (assuming label "1" means malware)
            malware_in_batch = (predictions == 1).sum().item()
            malware_count = malware_count + malware_in_batch


            # Calculate correct predictions (optionally, filter out ignore_index if necessary)
            # If your labels contain the ignore index (-1), then you need extra filtering.
            correct_predictions = (predictions == batch_labels).sum().item()
            total_predictions = batch_labels.size(0)
            wrong_predictions = total_predictions - correct_predictions
            accuracy = (correct_predictions / total_predictions) * 100 if total_predictions > 0 else 0

            # Print detailed results per batch
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

    return avg_loss , accuracy ,malware_count