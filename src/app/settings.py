import asyncio
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient
from odmantic import AIOEngine
from pydantic_settings import BaseSettings

from app.models.user import User


class Settings(BaseSettings):
    MONGO_URI: Optional[str] = "mongodb://root:password@localhost:27017/"


SETTINGS = Settings()

motor_client = AsyncIOMotorClient(SETTINGS.MONGO_URI)
engine = AIOEngine(motor_client, database="test")


