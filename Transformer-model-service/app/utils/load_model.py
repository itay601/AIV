import torch

def load_model(model, optimizer, scheduler=None, path='checkpoint.pth', device='cpu'):
    """
    Load the model and optimizer states from a checkpoint file.

    Args:
        model: The model to load the state into.
        optimizer: The optimizer to load the state into.
        path: File path where the checkpoint is stored.
        device: Device on which to map the checkpoint (e.g., 'cpu' or 'cuda').

    Returns:
        model: The model loaded with the checkpoint state.
        optimizer: The optimizer loaded with the checkpoint state.
        start_epoch: The next epoch to start from.
        loss: The loss value stored in the checkpoint.
    """
    checkpoint = torch.load(path, map_location=device)
    model.load_state_dict(checkpoint['model_state_dict'])
    optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
    scheduler.load_state_dict(checkpoint['scheduler_state_dict'])
    #start_epoch = checkpoint['epoch'] + 1
    # Move optimizer internal states to the proper device
    for state in optimizer.state.values():
        for k, v in state.items():
            if isinstance(v, torch.Tensor):
                state[k] = v.to(device)
    loss = checkpoint['loss']
    print(f"Loaded checkpoint '{path}' ")
    return model, optimizer, scheduler, loss
