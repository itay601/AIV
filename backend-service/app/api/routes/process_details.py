from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from models.schemas import Process ,ProcessResponse
from api.utils import append_process_to_csv
import httpx


router = APIRouter(prefix="/process")


@router.post("/process-service")
async def process_to_csv(request: Request, processes: list[Process]) -> None: #ProcessResponse:
    for process in processes:
        append_process_to_csv(process)
        
'''
@router.post("/process-service")
async def process_to_csv(request: Request, processes: list[Process]) -> None: #ProcessResponse:
    try:
        
        url = "http://localhost:5001/process-service"
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
            return ProcessResponse(
                packets=packets,
                message="mallicios packets check another model processes",
                success=True
        )
    except Exception as e:
        return ProcessResponse(
            packets=packets,
            message=f"Error sending packets: {e}",
            success=False
        )'''