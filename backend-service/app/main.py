from fastapi import FastAPI, Response, APIRouter

from api.routes.packet_sniffer import router as packets_router


app = FastAPI(prefix="/v1/api")

app.include_router(packets_router)


@app.get("/")
async def index():
    return {"message": "server is running"}


@app.get("/root")
async def root():
    return {"message": "server is running"}





