import base64
import os
from enum import Enum
from typing import Optional

from PIL import Image, ImageDraw, ImageFont
from fastapi import APIRouter, Request, Form, HTTPException, Depends, Body
from fastapi.responses import HTMLResponse, Response, FileResponse

from app.auth.service import find_user_by_username, get_user_from_cookie
from app.auth.model import User, Password
from app.settings import templates, engine
from app.utils import validate_password, Complexity

router = APIRouter()


class Permission(Enum):
    WRITE = "WRITE"
    READ = "READ"


files_perms = {
    "text.txt": {
        "permissions": {
            "admin": [Permission.READ, Permission.WRITE],
            "user": [Permission.READ]
        }
    },
    "picture.jpg": {
        "permissions": {
            "admin": [Permission.READ, Permission.WRITE],
            "user": [Permission.READ]
        }
    },
    "elex_setup.exe": {
        "permissions": {
            "admin": [Permission.READ, Permission.WRITE],
            "user": [Permission.READ]
        }
    }
}


def check_permission(filename: str, user_access: str, permission: Permission) -> bool:
    file_perm = files_perms.get(filename)
    if not file_perm:
        return False

    access_perms = file_perm.get("permissions")
    if not access_perms:
        return False

    user_perms = access_perms.get(user_access)
    if not user_perms:
        return False

    return permission in user_perms


@router.get("/register", response_class=HTMLResponse)
async def register_user(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name="register.html"
    )


@router.post("/register")
async def register_user_post(request: Request, username: str = Form(...), password: str = Form(...),
                             access: Optional[str] = Form("user"),
                             use_strong_password: Optional[bool] = Form(False,
                                                                        alias="use-strong-password")) -> HTMLResponse:
    password_type = validate_password(password)

    if await find_user_by_username(engine, username):
        return templates.TemplateResponse(
            request=request, name="register.html", context={"registered": False}
        )

    if use_strong_password and password_type != Complexity.STRONG.value:
        return templates.TemplateResponse(
            request=request, name="register.html", context={"registered": False}
        )

    user = User(username=username, password=Password(value=password, type=password_type, history=[password]),
                access_level=access)
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


@router.get("/user/change-password")
async def change_password(request: Request, username: str = Depends(get_user_from_cookie)):
    if not username:
        response = Response(status_code=307, headers={"Location": "http://localhost:8000/login"})
        return response
    else:

        return templates.TemplateResponse(
            request=request, name="change-password.html")


@router.post("/user/change-password")
async def change_password(request: Request, password: str = Form(...), username: str = Depends(get_user_from_cookie)):
    if not username:
        return redirect_to_login()

    user = await find_user_by_username(engine, username)

    if password in user.password.history:
        return render_change_password(False)

    if user.password.type == Complexity.STRONG.value:
        password_type = validate_password(password)
        if password_type == Complexity.STRONG.value:
            await update_password(user, password)
            return render_change_password(request, True)

    await update_password(user, password)
    return render_change_password(request, True)


@router.get("/user/files")
async def user_files(request: Request):
    file_list = []

    for root, directories, files in os.walk("./data"):
        for file in files:
            file_list.append(file)

    return templates.TemplateResponse(
        request=request, name="files.html", context={"files": file_list}
    )


@router.get("/user/files/{filename}")
async def user_file(request: Request, filename: str, username: str = Depends(get_user_from_cookie)):
    user = await find_user_by_username(engine, username)

    has_right = check_permission(filename, user.access_level, Permission.WRITE)

    try:
        if filename.endswith("jpg"):
            with open(f"./data/{filename}", "rb") as f:
                content = base64.b64encode(f.read()).decode('utf-8')

            return templates.TemplateResponse(
                request=request, name="file.html",
                context={"filename": filename, "content": content, "image": True, "has_right": has_right}
            )
        elif filename.endswith("txt"):
            with open(f"./data/{filename}", "r", encoding="utf-8") as f:
                content = f.read()

            return templates.TemplateResponse(
                request=request, name="file.html",
                context={"filename": filename, "content": content, "has_right": has_right}
            )
        elif filename.endswith("exe"):
            return templates.TemplateResponse(
                request=request, name="file.html",
                context={"filename": filename}
            )
    except Exception:
        return templates.TemplateResponse(
            request=request, name="file.html"
        )


@router.get("/user/files/{filename}/edit")
async def user_file_edit(request: Request, filename: str, username: str = Depends(get_user_from_cookie)):
    user = await find_user_by_username(engine, username)

    has_right = check_permission(filename, user.access_level, Permission.WRITE)

    if not has_right:
        return templates.TemplateResponse(
            request=request, name="edit-file.html"
        )

    try:
        if filename.endswith("jpg"):
            with open(f"./data/{filename}", "rb") as f:
                content = base64.b64encode(f.read()).decode('utf-8')

            return templates.TemplateResponse(
                request=request, name="edit-file.html",
                context={"filename": filename, "content": content, "image": True}
            )
        elif filename.endswith("txt"):
            with open(f"./data/{filename}", "r+", encoding="utf-8") as f:
                content = f.read()

            return templates.TemplateResponse(
                request=request, name="edit-file.html", context={"filename": filename, "content": content}
            )
        elif filename.endswith("exe"):
            print('test')
            return FileResponse(f"./data/{filename}", filename=filename)
    except Exception as e:
        return templates.TemplateResponse(
            request=request, name="edit-file.html"
        )


@router.post("/write/{filename}")
async def user_files_edit_post(filename: str, content: str = Body(...)):
    filetype = filename.split('.')[1]
    if filetype == "txt":
        try:
            with open(f"./data/{filename}", "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            raise e

    if filetype == "jpg":
        font = ImageFont.truetype("./RobotoMono.ttf", 34)
        im = Image.open(f"./data/{filename}")
        d = ImageDraw.Draw(im)
        d.text((100, 100), content, fill="blue", anchor="ms", font=font)
        im.save(f"./data/{filename}")
        print("save")

    if filetype == "exe":
        os.startfile(filename)


def redirect_to_login():
    return Response(status_code=307, headers={"Location": "http://localhost:8000/login"})


def render_change_password(request, changed):
    return templates.TemplateResponse(
        request=request, name="change-password.html", context={"changed": changed})


async def update_password(user, password):
    user.password.value = password
    if len(user.password.history) == 3:
        user.password.history.pop()
    user.password.history.insert(0, password)
    await engine.save(user)
