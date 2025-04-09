from fastapi import FastAPI, Response, APIRouter 
from routes.packet_AE import router as packets_router


app = FastAPI(prefix="/v1/transformer")

app.include_router(packets_router)


@app.get("/")
async def index():
    return {"message": "server is running"}