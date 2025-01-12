from fastapi import FastAPI, HTTPException ,APIRouter, Request
from typing import Annotated, Optional



router = APIRouter(prefix="/v1/xxx")


@router.post("/someEndpoint")
async def func(request: Request, input_data: something):
    return {"s":"s"}