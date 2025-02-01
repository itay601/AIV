from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from models.schemas import Packet ,PacketResponse
from api.utils import process_and_save_packets

router = APIRouter(prefix="/packets")


@router.post("/someEndpoint")
async def func(request: Request, input_data: Packet):
    return {"s":"s"}




@router.post("/packets-service")
async def process_packets(request: Request, packets: List[Packet]) -> PacketResponse:
    # Make a request to the backend service with the packets
    try:
        url = "http://backend-service.com/packets-endpoint"
        headers = {"Content-Type": "application/json"}
        response = requests.post(url, headers=headers, json=[packet.dict() for packet in packets])
        response.raise_for_status()
        return PacketResponse(packets=packets, message="Packets sent successfully")
    except requests.exceptions.RequestException as e:
        return PacketResponse(packets=packets, message=f"Error sending packets: {e}")