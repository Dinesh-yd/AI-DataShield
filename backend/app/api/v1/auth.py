from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.v1.utils import get_or_create_user
from app.core.database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


class AuthRequest(BaseModel):
    email: EmailStr
    name: str = "Demo User"


@router.post("/register")
def register(payload: AuthRequest, db: Session = Depends(get_db)):
    user = get_or_create_user(db, payload.email, payload.name)
    return {"id": user.id, "email": user.email, "name": user.name}


@router.post("/login")
def login(payload: AuthRequest, db: Session = Depends(get_db)):
    user = get_or_create_user(db, payload.email, payload.name)
    return {"id": user.id, "email": user.email, "name": user.name}
