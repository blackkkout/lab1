from odmantic import AIOEngine
from fastapi import Request

from app.auth.model import User


async def find_user_by_username(engine: AIOEngine, username: str) -> User:
    return await engine.find_one(User, User.username == username)


def get_user_from_cookie(request: Request):
    return request.cookies.get("username")
