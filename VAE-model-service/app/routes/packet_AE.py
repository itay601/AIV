from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
import pandas as pd
from models.packet_schema import Packet ,PacketResponse
from core.data_encodding import process_network_data
from core.ae_model import AutoEncoder , create_loader


router = APIRouter(prefix="")


# Must to List Of Packets!!!
@router.post("/packets-service")
async def process_packets(request: Request, packets: list[Packet]) -> PacketResponse: 
    # TODO 
    # -[X] need to get the list of analyzed packets and mybe take another process on Data .send to 2 DL-models services 
    # -[V] make CVE file of data  
    df = pd.DataFrame(packets)
    df = process_network_data(df)
    df = df.drop(columns=['HTTP_IsPOST'])
    val_loader = create_loader(processedd_df,100)
    prediction = predict(val_loader )
    #print(packets[0])
    return prediction


async def predict(val_loader):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    MODEL = load_model("app/autoencoder_checkpoint.pth")
    with torch.no_grad():
        for batch in val_loader:
            inputs = batch[0].to(device, non_blocking=True)
            output = MODEL(inputs)  
            val_loss += nn.functional.mse_loss(outputs, inputs).item()
            print("Model Predictions:", (outputs > 0.5).float())
            
                
    print(val_loss/len(val_loader)) ## should be like (5 - 20)
    if val_loss < 5 | val_loss > 20:
        print("Malicious Packet Detected!")
        return {"msg" : "Malicious Packet Detected! , check your computer now!!!"}
    else:
        print("Normal Packet")
        return {"msg" : "regular packets"}

