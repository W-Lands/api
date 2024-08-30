import json
from datetime import datetime
from io import BytesIO
from time import mktime, time
from uuid import uuid4

from PIL import Image
from bcrypt import checkpw
from fastapi import FastAPI, Depends, Response, UploadFile
from s3lite import S3Exception

from .dependencies import sess_auth_expired, user_auth
from .schemas import LoginData, TokenRefreshData, PatchUserData, PresignUrl, UploadProfile
from .utils import Mfa, getImage
from ..config import S3
from ..exceptions import CustomBodyException
from ..models import User, GameSession, Update, AllowedMod

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

    if user.banned:
        raise CustomBodyException(400, {"code": ["User is banned."]})

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
        "admin": user.admin,
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
    updates_ = await Update.filter(is_base=False, id__gt=version, pending=False).order_by("id")
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
    updates = await Update.filter(is_base=True, pending=False).order_by("id")
    updates = [{"os": upd.os, "arch": upd.arch, "files": upd.files} for upd in updates]

    return {
        "version": -1,
        "updates": updates,
    }


@app.get("/mods")
async def get_allowed_mods():
    ids: set[str] = set()
    classes: set[str] = set()
    for mod in await AllowedMod.all():
        ids.add(mod.hashed_id)
        classes.update(mod.classes)

    return {
        "ids": list(ids),
        "classes": list(classes),
    }


@app.post("/logs", status_code=204)
async def upload_logs(log: UploadFile, session: str | None = None, user: User = Depends(user_auth)):
    date = datetime.utcnow().strftime("%d%m%Y")
    if log.size > 1024 * 1024 * 16:
        return

    if session is None:
        session = time() // 86400

    file = BytesIO(await log.read())
    await S3.upload_object("wlands", f"logs/{date}/{user.id}/{session}/{int(time() % 86400)}.txt", file)


@app.post("/storage/presign")
async def presign_s3(data: PresignUrl, user: User = Depends(user_auth)):
    if not user.admin:
        raise CustomBodyException(403, {"user": ["Insufficient privileges."]})

    return {
        "url": S3.share("wlands-updates", data.key, 60 * 60, True)
    }


@app.post("/profiles/{profile}")
async def upload_url(profile: str, data: UploadProfile, user: User = Depends(user_auth)):
    if not user.admin:
        raise CustomBodyException(403, {"user": ["Insufficient privileges."]})

    try:
        manifest: dict = json.load(
            await S3.download_object("wlands-updates", "/profiles/.metadata.json", in_memory=True)
        )
    except S3Exception as e:
        manifest: dict = {"profiles": {}}
        data.set_current = True

    version = (manifest["profiles"][profile]["version"] + 1) if profile in manifest["profiles"] else 1
    manifest["profiles"][profile] = {
        "version": version,
        "manifest": data.manifest_url,
        "game_files": data.model_dump(include={"game_files"})["game_files"],
        "profile_files": data.model_dump(include={"profile_files"})["profile_files"],
    }
    if data.set_current:
        manifest["current"] = profile

    file = BytesIO(json.dumps(manifest).encode("utf8"))
    await S3.upload_object("wlands-updates", "/profiles/.metadata.json", file)

    return manifest["profiles"][profile]

