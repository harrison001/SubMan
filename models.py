# models.py
from pydantic import BaseModel, EmailStr
from typing import Optional

class User(BaseModel):
    email: EmailStr
    is_subscribed: Optional[bool] = False
    subscription_id: Optional[str] = None
    whatsapp_id: Optional[str] = None
    telegram_id: Optional[str] = None
    discord_id: Optional[str] = None
    line_id: Optional[str] = None

class Subscription(BaseModel):
    user_email: EmailStr
    subscription_id: str

class VerificationCode(BaseModel):
    user_email: EmailStr
    code: str