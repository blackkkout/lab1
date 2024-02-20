import os
from typing import Optional

from fastapi import Request
from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
from odmantic import AIOEngine
from pydantic_settings import BaseSettings

from app.auth.service import get_user_from_cookie

TEMPLATES_DIR = f"{os.path.dirname(__file__)}/templates"


def get_username(request: Request):
    username = get_user_from_cookie(request)

    return {"username": username}


templates = Jinja2Templates(directory=TEMPLATES_DIR, context_processors=[get_username])


class Settings(BaseSettings):
    MONGO_URI: Optional[str] = "mongodb://root:password@localhost:27017/"


SETTINGS = Settings()

motor_client = AsyncIOMotorClient(SETTINGS.MONGO_URI)
engine = AIOEngine(motor_client, database="test")
