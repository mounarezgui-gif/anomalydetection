from bson import ObjectId
from pymongo import ReturnDocument
from fastapi import APIRouter, HTTPException, Depends, status

from app.auth.database import users_collection
from app.auth.models import UserRegister, UserLogin, UserOut, TokenResponse, UserUpdateRole
from app.auth.security import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    require_role,
)

router = APIRouter(prefix="/auth", tags=["Authentification"])


def user_doc_to_out(user: dict) -> UserOut:
    return UserOut(
        id=str(user["_id"]),
        nom=user["nom"],
        email=user["email"],
        role=user["role"],
    )


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister):
    existing = await users_collection.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Un compte existe déjà avec cet email")

    user_doc = {
        "nom": payload.nom,
        "email": payload.email,
        "password": hash_password(payload.password),
        "role": "user",  # rôle forcé côté serveur, jamais fourni par le client
    }
    result = await users_collection.insert_one(user_doc)
    user_doc["_id"] = result.inserted_id

    token = create_access_token({"sub": str(user_doc["_id"]), "role": "user"})
    return TokenResponse(access_token=token, user=user_doc_to_out(user_doc))


@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin):
    user = await users_collection.find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")

    token = create_access_token({"sub": str(user["_id"]), "role": user["role"]})
    return TokenResponse(access_token=token, user=user_doc_to_out(user))


@router.get("/me", response_model=UserOut)
async def get_me(current_user: dict = Depends(get_current_user)):
    return user_doc_to_out(current_user)


# ---- Routes réservées à l'admin ----

@router.get("/users", response_model=list[UserOut])
async def list_users(current_user: dict = Depends(require_role("admin"))):
    users = await users_collection.find().to_list(length=500)
    return [user_doc_to_out(u) for u in users]


@router.patch("/users/{user_id}/role", response_model=UserOut)
async def update_user_role(
    user_id: str,
    payload: UserUpdateRole,
    current_user: dict = Depends(require_role("admin")),
):
    result = await users_collection.find_one_and_update(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": payload.role}},
        return_document=ReturnDocument.AFTER,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return user_doc_to_out(result)