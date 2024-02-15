import os
from typing import Optional

from fastapi.templating import Jinja2Templates
from motor.motor_asyncio import AsyncIOMotorClient
from odmantic import AIOEngine
from pydantic_settings import BaseSettings

TEMPLATES_DIR = f"{os.path.dirname(__file__)}/templates"

templates = Jinja2Templates(directory=TEMPLATES_DIR)


class Settings(BaseSettings):
    MONGO_URI: Optional[str] = "mongodb://root:password@localhost:27017/"


SETTINGS = Settings()

motor_client = AsyncIOMotorClient(SETTINGS.MONGO_URI)
engine = AIOEngine(motor_client, database="test")
