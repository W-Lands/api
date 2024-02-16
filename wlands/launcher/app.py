from io import BytesIO
from time import mktime
from uuid import uuid4

from PIL import Image
from bcrypt import checkpw
from fastapi import FastAPI, Depends, Response

from .dependencies import sess_auth_expired, user_auth
from .schemas import LoginData, TokenRefreshData, PatchUserData
from .utils import Mfa, getImage
from ..config import S3
from ..exceptions import CustomBodyException
from ..models import User, GameSession, Update

app = FastAPI()


@app.post("/auth/login")
async def login(data: LoginData):
    if (user := await User.get_or_none(email=data.email)) is None:
        raise CustomBodyException(400, {"email": ["User with this email/password does not exists."]})

    if not checkpw(data.password.encode(), user.password.encode()):
        raise CustomBodyException(400, {"email": ["User with this email/password does not exists."]})

    code = Mfa.getCode(user)
    if code is not None and code != data.code:
        raise CustomBodyException(400, {"code": ["Incorrect 2fa code."]})

    session = await GameSession.create(user=user)

    return {
        "token": f"{user.id.hex}{session.id.hex}{session.token}",
        "refresh_token": f"{user.id.hex}{session.id.hex}{session.refresh_token}",
        "expires_at": mktime(session.expires_at.timetuple()),
    }


@app.post("/auth/refresh")
async def refresh_session(data: TokenRefreshData, session: GameSession = Depends(sess_auth_expired)):
    user = session.user

    refresh_token = data.refresh_token
    user_id_hex = refresh_token[:32]
    session_id_hex = refresh_token[32:64]
    refresh_token = refresh_token[64:]

    if session.refresh_token != refresh_token or user_id_hex != user.id.hex or session_id_hex != session.id.hex:
        raise CustomBodyException(400, {"refresh_token": ["Invalid refresh token."]})

    new_session = await GameSession.create(user=user)
    await session.delete()

    return {
        "token": f"{user.id.hex}{new_session.id.hex}{new_session.token}",
        "refresh_token": f"{user.id.hex}{new_session.id.hex}{new_session.refresh_token}",
        "expires_at": mktime(new_session.expires_at.timetuple()),
    }


@app.post("/auth/logout", status_code=204)
async def logout(session: GameSession = Depends(sess_auth_expired)):
    await session.delete()


@app.get("/auth/verify")
async def check_session(session: GameSession = Depends(sess_auth_expired)):
    return Response("{}", 207 if session.expired else 200)


@app.get("/users/@me")
async def get_me(user: User = Depends(user_auth)):
    return {
        "id": user.id,
        "email": user.email,
        "nickname": user.nickname,
        "skin": user.skin_url,
        "cape": user.cape_url,
        "mfa": user.mfa_key is not None,
        "signed_for_beta": user.signed_for_beta,
    }


def reencode(file: BytesIO) -> BytesIO:
    img = Image.open(file)
    out = BytesIO()
    img.save(out, format="PNG")
    return out


async def edit_texture(user: User, name: str, image: str):
    if (texture := getImage(image)) is not None:
        texture = reencode(texture)
        texture_id = uuid4()
        await S3.upload_object("wlands", f"{name}s/{user.id}/{texture_id}.png", texture)
        await user.update(**{name: texture_id})
    elif image == "":
        await user.update(**{name: None})


@app.patch("/users/@me")
async def edit_me(data: PatchUserData, user: User = Depends(user_auth)):
    await edit_texture(user, "skin", data.skin)
    await edit_texture(user, "cape", data.cape)

    return await get_me(user)


@app.get("/updates")
async def get_updates(version: int = 0):
    updates_ = await Update.filter(is_base=True, id__gt=version).order_by("id")
    updates = []
    latestVersion = version
    for upd in updates_:
        latestVersion = max(latestVersion, upd.id)
        updates.append({"os": upd.os, "arch": upd.arch, "files": upd.files})

    return {
        "version": latestVersion,
        "updates": updates,
    }


@app.get("/updates/base")
async def get_base_updates():
    updates = await Update.filter(is_base=True).order_by("id")
    updates = [{"os": upd.os, "arch": upd.arch, "files": upd.files} for upd in updates]

    return {
        "version": -1,
        "updates": updates,
    }
