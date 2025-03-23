from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from models.schemas import Packet ,PacketResponse
from api.utils import process_and_save_packets
import httpx


router = APIRouter(prefix="/packets")


@router.post("/packets-service")
async def process_packets(request: Request, packets: list[Packet]) -> PacketResponse:
    try:
        #localhost NOT important for now
        url = "http://localhost:5001/packets-service"
        headers = {"Content-Type": "application/json"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url, 
                headers=headers, 
                json=[packet.dict() for packet in packets]
            )
            response.raise_for_status()
        response_data = response.json()
        message = response_data.message
        if message != "regular packets":    
            return PacketResponse(
                packets=packets,
                message="mallicios packets check another model processes",
                success=True
        )
    except Exception as e:
        return PacketResponse(
            packets=packets,
            message=f"Error sending packets: {e}",
            success=False
        )