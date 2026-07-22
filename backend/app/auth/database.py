import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()

# Connexion dédiée à l'authentification
MONGODB_URI_AUTH = os.getenv("MONGODB_URI_AUTH")
MONGODB_DB_AUTH = os.getenv("MONGODB_DB_AUTH", "authentification")

if not MONGODB_URI_AUTH:
    raise RuntimeError("MONGODB_URI_AUTH manquant dans le .env")

client = AsyncIOMotorClient(MONGODB_URI_AUTH)
db = client[MONGODB_DB_AUTH]

users_collection = db["users"]