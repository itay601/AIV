from fastapi import FastAPI, Response, APIRouter

#from routers.users import router as users_router


app = FastAPI()

#app.include_router(users_router)


@app.get("/")
async def index():
    return {"message": "server is running"}


@app.get("/root")
async def root():
    return {"message": "server is running"}