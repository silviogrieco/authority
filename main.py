from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from Authority import Authority


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

authority = Authority("data/keys/keys.json")
app.include_router(authority.router)