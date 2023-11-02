import uvicorn
from fastapi import FastAPI

from api.v1.accounts import routers as accounts_router


app = FastAPI()

app.include_router(accounts_router, prefix="/accounts")

if __name__ == "__main__":
    uvicorn.run("__main__:app", host="0.0.0.0", port=8001, reload=True)