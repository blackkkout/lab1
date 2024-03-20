import base64
import io
import os
from typing import Optional

from PIL import Image, ImageDraw, ImageFont
from fastapi import APIRouter, Request, Form, HTTPException, Depends, Body, UploadFile
from fastapi.responses import HTMLResponse, Response
from starlette.responses import  RedirectResponse, StreamingResponse

from app.auth.service import find_user_by_username, get_user_from_cookie
from app.auth.model import User, Password, Resource
from app.settings import templates, engine
from app.utils import validate_password, Complexity

router = APIRouter()

file_perms = {
    "public": 0,
    "non-secret": 1,
    "secret": 2
}

access_table = {
    "admin": 3,
    "user": 2
}


def check_permission(file_access_level, user_access_level):
    if access_table[user_access_level] > file_perms[file_access_level]:
        return True
    # elif access_table[user_access_level] == file_perms[file_access_level]:
    #     return False
    else:
        return None


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
    files = await engine.find(Resource)

    file_list = map(lambda x: x.filename, files)

    return templates.TemplateResponse(
        request=request, name="files.html", context={"files": file_list}
    )


@router.get("/user/files/{filename}")
async def user_file(request: Request, filename: str, username: str = Depends(get_user_from_cookie)):
    user = await find_user_by_username(engine, username)
    file = await engine.find_one(Resource, Resource.filename == filename)

    has_right = check_permission(file.access_level, user.access_level)

    print(has_right)

    if has_right is None:
        return templates.TemplateResponse(
            request=request, name="edit-file.html"
        )


    try:
        if filename.endswith("jpg"):
            content = file.content.decode('utf-8')
            return templates.TemplateResponse(
                request=request, name="file.html",
                context={"filename": filename, "content": content, "image": True, "has_right": True}
            )
        elif filename.endswith("txt"):
            content = base64.b64decode(file.content).decode('utf-8')
            print(content)

            return templates.TemplateResponse(
                request=request, name="file.html",
                context={"filename": filename, "content": content, "has_right": True}
            )
        elif filename.endswith("exe"):
            return templates.TemplateResponse(
                request=request, name="file.html",
                context={"filename": filename}
            )
    except Exception as e:
        return templates.TemplateResponse(
            request=request, name="file.html"
        )


@router.get("/user/files/{filename}/edit")
async def user_file_edit(request: Request, filename: str, username: str = Depends(get_user_from_cookie)):
    user = await find_user_by_username(engine, username)
    file = await engine.find_one(Resource, Resource.filename == filename)

    has_right = check_permission(file.access_level, user.access_level)


    if has_right is not True:
        return templates.TemplateResponse(
            request=request, name="edit-file.html"
        )
    try:
        if filename.endswith("jpg"):
            content = file.content.decode('utf-8')

            return templates.TemplateResponse(
                request=request, name="edit-file.html",
                context={"filename": filename, "content": content, "image": True}
            )
        elif filename.endswith("txt"):
            content = base64.b64decode(file.content).decode('utf-8')

            return templates.TemplateResponse(
                request=request, name="edit-file.html", context={"filename": filename, "content": content}
            )
        elif filename.endswith("exe"):
            return StreamingResponse(io.BytesIO(base64.b64decode(file.content)), media_type="application/octet-stream")
    except Exception as e:
        return templates.TemplateResponse(
            request=request, name="edit-file.html"
        )


@router.post("/write/{filename}")
async def user_files_edit_post(filename: str, content: str = Body(...)):
    file = await engine.find_one(Resource, Resource.filename == filename)

    filetype = filename.split('.')[1]
    if filetype == "txt":
        file.content = base64.b64encode(content.encode('utf-8'))
        await engine.save(file)

    if filetype == "jpg":
        font = ImageFont.truetype("./RobotoMono.ttf", 34)
        a = io.BytesIO(base64.b64decode(file.content))

        im = Image.open(a)
        d = ImageDraw.Draw(im)
        d.text((100, 100), content, fill="blue", anchor="ms", font=font)
        with io.BytesIO() as output:
            im.save(output, format="JPEG")
            file.content = base64.b64encode(output.getvalue())
            await engine.save(file)

    if filetype == "exe":
        os.startfile(filename)


@router.get("/create-resource")
async def create_resource_post(request: Request):
    return templates.TemplateResponse(
        request=request, name="create-resource.html"
    )


@router.post("/create-resource")
async def upload_file(file: UploadFile, access_level: str = Form("non-secret"), username: str = Depends(get_user_from_cookie)):
    user = await find_user_by_username(engine, username)
    print(file)
    resource = Resource(
        content=base64.b64encode(await file.read()),
        access_level=access_level,
        filename=file.filename,
        userId=user.id
    )
    await engine.save(resource)
    return RedirectResponse(url="/user")


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
