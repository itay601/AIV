from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional
from models.schemas import Process ,ProcessResponse , PEFilesDeatils , PEFilesDeatilsResponse
from api.utils import append_process_to_csv
import httpx


router = APIRouter(prefix="/process")


@router.post("/process_details_to_csv")
async def process_to_csv(request: Request, processes: list[Process]) -> None: 
    print(processes[0])
    for process in processes:
        append_process_to_csv(process)
        
#@router.post("/process-service")
#async def Analyzed_PE_files_transformer_servive(request: Request, detailed_PE_files: list[PEFilesDeatils]) -> PEFilesDeatilsResponse:

@router.post("/AnalyzedEmberEXEDLL")
async def Analyzed_PE_files_transformer_servive(request: Request, detailed_PE_files: list[PEFilesDeatils]) : 
    response_message = f"working :\n {detailed_PE_files}"
    return {"msg": response_message}
    #def preprocessing_data_from_cliend by
    '''try:
        #localhost NOT important for now
        url = "http://localhost:5001/transformer"
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
        if message != "non malicious":    
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
