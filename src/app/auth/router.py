from typing import Optional

from fastapi import APIRouter, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, Response

from app.auth.service import find_user_by_username, get_user_from_cookie
from app.auth.model import User, Password
from app.settings import templates, engine
from app.utils import validate_password, PasswordComplexity

router = APIRouter()


@router.get("/register", response_class=HTMLResponse)
async def register_user(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name="register.html"
    )


@router.post("/register")
async def register_user_post(request: Request, username: str = Form(...), password: str = Form(...),
                             use_strong_password: Optional[bool] = Form(False,
                                                                        alias="use-strong-password")) -> HTMLResponse:
    password_type = validate_password(password)

    if await find_user_by_username(engine, username):
        return templates.TemplateResponse(
            request=request, name="register.html", context={"registered": False}
        )

    if use_strong_password and password_type != PasswordComplexity.STRONG.value:
        return templates.TemplateResponse(
            request=request, name="register.html", context={"registered": False}
        )

    user = User(username=username, password=Password(value=password, type=password_type))
    await engine.save(user)
    return templates.TemplateResponse(
        request=request, name="register.html", context={"registered": True}
    )


@router.get("/login", response_class=HTMLResponse)
async def login_user(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name="login.html"
    )


@router.post("/login", response_class=HTMLResponse)
async def login_user_post(username: str = Form(...), password: str = Form(...)):
    user = await find_user_by_username(engine, username)

    print(user)

    if not user or user.password.value != password:
        return HTTPException(status_code=406)

    response = Response(status_code=307, headers={"Location": "/user"})
    response.set_cookie("username", user.username)
    return response


@router.get("/user")
async def get_user(request: Request, username: str = Depends(get_user_from_cookie)):
    if not username:
        response = Response(status_code=307, headers={"Location": "http://localhost:8000/login"})
        return response
    else:
        return templates.TemplateResponse(
            request=request, name="user.html", context={"username": username},
        )


@router.post("/user")
async def get_user_post(request: Request, username: str = Depends(get_user_from_cookie)):
    if not username:
        response = Response(status_code=307, headers={"Location": "http://localhost:8000/login"})
        return response
    else:
        return templates.TemplateResponse(
            request=request, name="user.html", context={"username": username},
        )
