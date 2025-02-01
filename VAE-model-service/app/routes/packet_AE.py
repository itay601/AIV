from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from models.schemas import Packet ,PacketResponse


router = APIRouter(prefix="/packets")


# Must to List Of Packets!!!
@router.post("/packets-service")
async def process_packets(request: Request, packets: list[Packet]) -> PacketResponse: 
    # TODO 
    # -[X] need to get the list of analyzed packets and mybe take another process on Data .send to 2 DL-models services 
    # -[V] make CVE file of data  
    