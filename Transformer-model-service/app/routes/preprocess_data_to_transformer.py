from fastapi import FastAPI, Response, APIRouter ,Request
from preprocessing.exact_features import preprocessing_data_files
from models.ember_structure import PEFilesDeatils
from models.transformer_models import initialize_model ,setup_optimizer
from utils.load_model import load_model
from utils.evaluation import eval_model

import torch
import torch.nn as nn


router = APIRouter(prefix="")


@router.post("/transformer-service")
async def process_packets(request: Request, files: list[PEFilesDeatils]) -> dict : 
    d_model = 128
    data_loader = preprocessing_data_files(files)
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = initialize_model(
        d_model=d_model,
        nhead=8,
        num_encoder_layers=6,
        num_latents=8,
        moe_hidden_dim=1024,
        num_experts=8,
        num_classes=2,
        dropout=0.25
    )

    # Setup loss criterion (optimizer and scheduler are not needed in evaluation)
    criterion = nn.CrossEntropyLoss(ignore_index=-1)

    optimizer, scheduler = setup_optimizer(model, 0.001, 1e-4)

    model, optimizer, scheduler, loss = load_model(model = model, optimizer = optimizer, scheduler=scheduler, path='transformer.pth',device=device)
    model = model.to(device)

    # Run evaluation
    avg_loss = eval_model(
        model=model,
        eval_loader=data_loader,
        criterion=criterion,
        device=device
    )    
#####################################
   



