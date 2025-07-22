from hashlib import sha1
from io import BytesIO
from uuid import UUID

from bcrypt import gensalt, hashpw, checkpw
from fastapi import FastAPI, Request, Header
from starlette.responses import JSONResponse
from tortoise.contrib.fastapi import register_tortoise
from tortoise.expressions import Q

from .schemas import CreateUser, EditUser, CreateUpdate
from ..config import DATABASE_URL, INTERNAL_AUTH_TOKEN, S3, S3_ENDPOINT
from ..exceptions import CustomBodyException
from ..launcher.app import edit_texture
from ..models import User, TgUser, GameSession, UserSession, Update

app = FastAPI()

register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["wlands.models"]},
    generate_schemas=True,
    add_exception_handlers=False,
)


@app.exception_handler(CustomBodyException)
async def custom_exception_handler(request: Request, exc: CustomBodyException):
    return JSONResponse(status_code=exc.code, content=exc.body)


@app.post("/users/")
async def create_user(data: CreateUser, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if data.telegram_id is not None and await TgUser.filter(id=data.telegram_id).exists():
        raise CustomBodyException(400, {"error_message": "User with this telegram account already exists"})

    if await User.filter(Q(email=data.email) | Q(nickname=data.login)).exists():
        raise CustomBodyException(400, {"error_message": "User with this email or nickname already exists"})

    password = hashpw(data.password.encode("utf8"), gensalt()).decode("utf8")
    user = await User.create(email=data.email, nickname=data.login, password=password)
    if data.telegram_id is not None:
        await TgUser.create(id=data.telegram_id, user=user)

    return {"id": user.id}


@app.get("/users/{user_id}")
async def get_user(user_id: UUID, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if (user := await User.get_or_none(id=user_id)) is None:
        raise CustomBodyException(400, {"error_message": "User not found."})

    return {
        "id": user.id,
        "email": user.email,
        "nickname": user.nickname,
        "skin": user.skin,
        "cape": user.cape,
        "mfa": user.mfa_key is not None,
        "signed_for_beta": user.signed_for_beta,
        "banned": user.banned,
    }


@app.patch("/users/{user_id}")
async def edit_user(user_id: UUID, data: EditUser, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if (user := await User.get_or_none(id=user_id)) is None:
        raise CustomBodyException(400, {"error_message": "User not found."})

    if data.new_password is not None:
        if data.password is None or not checkpw(data.password.encode("utf8"), user.password.encode("utf8")):
            raise CustomBodyException(400, {"error_message": "Old password is wrong."})

        user.password = hashpw(data.password.encode("utf8"), gensalt()).decode("utf8")
        await user.save(update_fields=["password"])

    await edit_texture(user, "skin", data.skin)
    await edit_texture(user, "cape", data.cape)

    return {
        "id": user.id,
        "email": user.email,
        "login": user.nickname,
        "skin": user.skin_url,
        "cape": user.cape_url,
        "mfa": user.mfa_key is not None,
        "signed_for_beta": user.signed_for_beta,
        "banned": user.banned,
    }


@app.post("/users/{user_id}/ban", status_code=204)
async def ban_user(user_id: UUID, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if (user := await User.get_or_none(id=user_id)) is None:
        raise CustomBodyException(400, {"error_message": "User not found."})

    if user.banned:
        raise CustomBodyException(400, {"error_message": "User already banned."})

    user.banned = True
    await user.save(update_fields=["banned"])
    await GameSession.filter(user=user).delete()
    await UserSession.filter(user=user).delete()


@app.post("/users/{user_id}/unban", status_code=204)
async def ban_user(user_id: UUID, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if (user := await User.get_or_none(id=user_id)) is None:
        raise CustomBodyException(400, {"error_message": "User not found."})

    if not user.banned:
        raise CustomBodyException(400, {"error_message": "User is not banned."})

    user.banned = False
    await user.save(update_fields=["banned"])


@app.post("/updates/new")
async def create_update(data: CreateUpdate, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    new_update = await Update.create(is_base=data.base, os=data.os, arch=data.arch, pending=True)

    return {"id": new_update.id}


@app.put("/updates/{update_id}/{file_path}", status_code=204)
async def upload_file(update_id: int, file_path: str, request: Request, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if (update := await Update.get_or_none(id=update_id)) is None:
        raise CustomBodyException(400, {"error_message": "Unknown update"})
    if not update.pending:
        raise CustomBodyException(400, {"error_message": "Cannot edit this update"})

    if update.is_base:
        update_id = f"b{update_id}"

    file = BytesIO(await request.body())
    sha1_hash = sha1(file.read()).digest()
    file.seek(0)
    await S3.upload_file("wlands-updates", f"{update_id}/{sha1_hash}", file)
    update.files.append(
        {"url": f"{S3_ENDPOINT}/wlands-updates/{update_id}/{sha1_hash}", "path": file_path, "hash": sha1_hash}
    )
    await update.save(update_fields=["files"])

    
@app.post("/updates/{update_id}", status_code=204)
async def save_update(update_id: int, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if (update := await Update.get_or_none(id=update_id)) is None:
        raise CustomBodyException(400, {"error_message": "Unknown update"})
    if not update.pending:
        raise CustomBodyException(400, {"error_message": "Cannot edit this update"})

    update.pending = False
    await update.save(update_fields=["pending"])
