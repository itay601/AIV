from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from models.schemas import Packet ,PacketResponse
from api.utils import process_and_save_packets

router = APIRouter(prefix="/packets")


@router.post("/someEndpoint")
async def func(request: Request, input_data: Packet):
    return {"s":"s"}

# Must to List Of Packets!!!
@router.post("/packets-service1")
async def process_packets(request: Request, packets: list[Packet]) -> PacketResponse: 
    # TODO 
    # - need to get the list of analyzed packets and mybe take another process on Data
    # and send him for check to the VAE DL model service for handeling 

    
    try:
        # Your processing logic here
        return PacketResponse(
            success=True,
            message="Packets processed successfully",
            data=packets
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# Must to List Of Packets!!!
@router.post("/packets-service")
async def process_packets(request: Request, packets: list[Packet]) -> PacketResponse: 
    # TODO 
    # - need to get the list of analyzed packets and mybe take another process on Data
    # - make CVE file of data  
    return await process_and_save_packets(packets)