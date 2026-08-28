"""
main.py (auth-service)
Service d'authentification, isolé du reste du pipeline d'analyse.

Lancer avec : uvicorn main:app --reload --port 8004
"""

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.routes import router as auth_router

app = FastAPI(
    title="Auth Service",
    description="Authentification et gestion des utilisateurs.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}