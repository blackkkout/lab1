import asyncio
from typing import Optional

import uvicorn
from fastapi import FastAPI, Request, Form, Response, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse, JSONResponse

from app.models.user import User
from app.settings import engine
from app.utils import validate_password

app = FastAPI()

templates = Jinja2Templates(directory="./src/app/templates")


@app.get("/register", response_class=HTMLResponse)
async def register_get(request: Request):
    return templates.TemplateResponse(
        request=request, name="register.html"
    )


@app.post("/register")
async def register_post(request: Request, username: str = Form(...), password: str = Form(...),
                        is_password_strong: Optional[bool] = Form(False, alias="is-strong-password")):
    password_type = validate_password(password)
    if is_password_strong and password_type != "strong":
        return templates.TemplateResponse(
            request=request, name="register.html", context={"success": False}
        )
    if await engine.find_one(User, User.username == username):
        return templates.TemplateResponse(
            request=request, name="register.html", context={"success": False}
        )
    user = User(username=username, password={"value": password, "type": password_type})
    await engine.save(user)
    return templates.TemplateResponse(
        request=request, name="register.html", context={"success": True}
    )


@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse(
        request=request, name="login.html"
    )


@app.post("/login", response_class=HTMLResponse)
async def login_post(username: str = Form(...), password: str = Form(...)):
    user = await engine.find_one(User, User.username == username)
    if user is not None and user.password.value == password:
        response = Response(status_code=307, headers={"Location": "/user"})
        response.set_cookie("username", user.username)
        return response
    raise HTTPException(status_code=406)


@app.post("/user", response_class=HTMLResponse)
async def user_get(request: Request):
    return request.cookies.get("username")


if __name__ == "__main__":
    async def fun():
        await engine.configure_database([User])


    asyncio.run(fun())
    uvicorn.run(app)
