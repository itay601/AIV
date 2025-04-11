from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from models.schemas import Process ,ProcessResponse , PEFilesDeatils , PEFilesDeatilsResponse
from api.utils import preprocessing_data_files
import httpx


router = APIRouter(prefix="/process")


@router.post("/process-service")
async def check_known_process_from_local_db(request: Request, processes: list[Process]) -> None: 
    response_message = f"{processes}"
    return {"msg": response_message}
        


@router.post("/AnalyzedEmberEXEDLL")
async def Analyzed_PE_files_transformer_servive(request: Request, detailed_PE_files: list[PEFilesDeatils]) : 
    response_message = f"{detailed_PE_files}"
    #return {"msg": response_message}
    #response_data = preprocessing_data_files(detailed_PE_files)
    return {"msg": response_message}
    try:
        #localhost NOT important for now
        url = "http://localhost:5002/transformer/exe-dll-files"
        headers = {"Content-Type": "application/json"}
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url, 
                headers=headers, 
                json=[file.dict() for file in detailed_PE_files]
            )
            response.raise_for_status()
        response_data = response.json()
        message = response_data.message
        #
        #need to make more work here 
        # Malware mybe detected what now ?
        if message == "Malware instances detected in evaluation":    
            return PEFilesDeatilsResponse(
                data=detailed_PE_files,
                message="mallicios files!! check another model processes",
                success=True
        )
    except Exception as e:
        return PacketResponse(
            packets=packets,
            message=f"Error sending packets: {e}",
            success=False
        ) '''
