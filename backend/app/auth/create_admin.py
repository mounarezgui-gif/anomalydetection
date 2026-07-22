"""
Lance ce script une fois pour créer le compte admin :
    python -m app.auth.create_admin
"""
import asyncio
import os
from dotenv import load_dotenv

from app.auth.database import users_collection
from app.auth.security import hash_password

load_dotenv()


async def create_admin():
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_email or not admin_password:
        print("Ajoute ADMIN_EMAIL et ADMIN_PASSWORD dans ton .env")
        return

    existing = await users_collection.find_one({"email": admin_email})
    if existing:
        print(f"Un compte existe déjà pour {admin_email} (role: {existing['role']})")
        return

    await users_collection.insert_one(
        {
            "nom": "Administrateur",
            "email": admin_email,
            "password": hash_password(admin_password),
            "role": "admin",
        }
    )
    print(f"Compte admin créé : {admin_email}")


if __name__ == "__main__":
    asyncio.run(create_admin())