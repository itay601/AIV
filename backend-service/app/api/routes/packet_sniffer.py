from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from api.schemas import Packet ,PacketResponse


router = APIRouter(prefix="/packets")


@router.post("/someEndpoint")
async def func(request: Request, input_data: Packet):
    return {"s":"s"}

# Must to List Of Packets!!!
@router.post("/packets-service")
async def process_packets(request: Request, packets: list[Packet]) -> PacketResponse: 
    try:
        # Your processing logic here
        return PacketResponse(
            success=True,
            message="Packets processed successfully",
            data=packets
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))