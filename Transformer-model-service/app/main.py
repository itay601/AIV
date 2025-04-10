from fastapi import FastAPI, Response, APIRouter 
from routes.preprocess_data_to_transformer import router as process_router


app = FastAPI(prefix="/v1/transformer")

app.include_router(process_router)


@app.get("/")
async def index():
    return {"message": "server is running"}