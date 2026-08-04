import os
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

load_dotenv()


def _get_mongodb_settings() -> tuple[str, str]:
    mongodb_uri = (
        os.getenv("MONGODB_URI_AUTH")
        or os.getenv("MONGODB_URI")
        or os.getenv("MONGODB_URI_ANALYSES")
    )
    if not mongodb_uri:
        raise RuntimeError(
            "Aucune URI MongoDB n’a été fournie. Définissez MONGODB_URI_AUTH, MONGODB_URI ou MONGODB_URI_ANALYSES."
        )

    mongodb_db = os.getenv("MONGODB_DB_AUTH") or os.getenv("MONGODB_DB_NAME") or "authentification"
    return mongodb_uri, mongodb_db


# Connexion dédiée à l'authentification
MONGODB_URI_AUTH, MONGODB_DB_AUTH = _get_mongodb_settings()

client = AsyncIOMotorClient(MONGODB_URI_AUTH)
db = client[MONGODB_DB_AUTH]

users_collection = db["users"]