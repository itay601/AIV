from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
import pandas as pd
from models.packet_schema import Packet ,PacketResponse
from core.data_encodding import process_network_data ,load_model
from core.ae_model import AutoEncoder , create_loader
import torch

router = APIRouter(prefix="")


# Must to List Of Packets!!!
@router.post("/packets-service")
async def process_packets(request: Request, packets: list[Packet]) -> dict : 
    df = pd.DataFrame(packets)
    df = process_network_data(df)
    val_loader = create_loader(df,30)
    prediction = await predict(val_loader)
    #print(packets[0])
    return {"success": True, "message": {prediction}}



async def predict(val_loader):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    MODEL = load_model("./autoencoder_checkpoint.pth")
    MODEL.to(device)  # Move the model to the same device
    MODEL.eval()      # Set the model to evaluation mode
    val_loss = 0.0

    with torch.no_grad():
        for batch in val_loader:
            inputs = batch[0].to(device, non_blocking=True)
            outputs = MODEL(inputs)  
            val_loss += torch.nn.functional.mse_loss(outputs, inputs).item()
            #print("Model Predictions:", (outputs > 0.5).float())

    avg_loss = val_loss / len(val_loader)
    #print(avg_loss)  # should be like (5 - 20)

    # Use logical operators (and/or) instead of bitwise operators (|) for conditions
    if avg_loss < 580 or avg_loss > 700:
        #print("Malicious Packet Detected!")
        return "Malicious Packet Detected!"
    else:
        #print("Normal Packet")
        return "regular packets"
