from asyncio import get_event_loop
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timezone
from io import BytesIO
from time import time
from uuid import uuid4

from PIL import Image
from bcrypt import checkpw
from fastapi import FastAPI, Depends, UploadFile
from pytz import UTC
from tortoise.expressions import Q

from .dependencies import sess_auth_expired, AuthUserOptDep, AuthUserDep, AuthSessExpDep
from .request_models import LoginData, TokenRefreshData, PatchUserData, PresignUrl
from .response_models import AuthResponse, SessionExpirationResponse, UserInfoResponse, ProfileInfo, ProfileFileInfo
from .utils import Mfa, getImage
from ..config import S3, S3_PUBLIC
from ..exceptions import CustomBodyException
from ..models import User, GameSession, GameProfile, ProfileFile

app = FastAPI()


@app.post("/auth/login", response_model=AuthResponse)
async def login(data: LoginData):
    query = Q(email=data.email) if "@" in data.email else Q(nickname=data.email)
    if (user := await User.get_or_none(query)) is None:
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
        "expires_at": int(session.expires_at.timestamp()),
    }


@app.post("/auth/refresh", response_model=AuthResponse)
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
        "expires_at": int(new_session.expires_at.timestamp()),
    }


@app.post("/auth/logout", status_code=204)
async def logout(session: AuthSessExpDep):
    await session.delete()


@app.get("/auth/verify", response_model=SessionExpirationResponse)
async def check_session(session: AuthSessExpDep):
    return {
        "expired": session.expired
    }


@app.get("/users/@me", response_model=UserInfoResponse)
async def get_me(user: AuthUserDep):
    return {
        "id": user.id,
        "email": user.email,
        "nickname": user.nickname,
        "skin": user.skin_url,
        "cape": user.cape_url,
        "mfa": user.mfa_key is not None,
        "admin": user.admin,
    }


def reencode(file: BytesIO) -> BytesIO:
    img = Image.open(file)
    out = BytesIO()
    img.save(out, format="PNG")
    return out


async def edit_texture(user: User, name: str, image: str) -> None:
    if (texture := getImage(image)) is not None:
        with ThreadPoolExecutor() as pool:
            texture = await get_event_loop().run_in_executor(pool, reencode, texture)
        texture_id = uuid4()
        await S3.upload_object("wlands", f"{name}s/{user.id}/{texture_id}.png", texture)
        setattr(user, name, texture_id)
        await user.save(update_fields=[name])
    elif image == "":
        setattr(user, name, None)
        await user.save(update_fields=[name])


@app.patch("/users/@me", response_model=UserInfoResponse)
async def edit_me(data: PatchUserData, user: AuthUserDep):
    await edit_texture(user, "skin", data.skin)
    await edit_texture(user, "cape", data.cape)

    return await get_me(user)


@app.post("/logs", status_code=204)
async def upload_logs(log: UploadFile, user: AuthUserDep, session: str | None = None):
    date = datetime.now(UTC).strftime("%d%m%Y")
    if log.size > 1024 * 1024 * 16:
        return

    if session is None:
        session = time() // 86400

    file = BytesIO(await log.read())
    await S3.upload_object("wlands", f"logs/{date}/{user.id}/{session}/{int(time() % 86400)}.txt", file)


@app.post("/storage/presign")
async def presign_s3(data: PresignUrl, user: AuthUserDep):
    if not user.admin:
        raise CustomBodyException(403, {"user": ["Insufficient privileges."]})

    return {
        "url": S3_PUBLIC.share("wlands-updates", data.key, 60 * 60, True)
    }


@app.get("/profiles", response_model=list[ProfileInfo])
async def get_profiles(user: AuthUserOptDep, with_manifest: bool = True, only_public: bool = True):
    only_public = only_public and user is not None and user.admin
    profiles_q = Q(public=True) if only_public else Q()

    profiles = await GameProfile.filter(profiles_q).order_by("-updated_at")

    return [
        profile.to_json(with_manifest)
        for profile in profiles
    ]


@app.get("/profiles/{profile_id}/files", response_model=list[ProfileFileInfo])
async def get_profile_files(profile_id: int, min_date: int = 0, max_date: int = 0):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise CustomBodyException(404, {"profile_id": ["Unknown profile."]})

    if min_date:
        min_date = datetime.fromtimestamp(max(int(profile.created_at.timestamp()), min_date), timezone.utc)
    else:
        min_date = profile.created_at
    if max_date:
        max_date = datetime.fromtimestamp(min(int(profile.updated_at.timestamp()), max_date), timezone.utc)
    else:
        max_date = profile.updated_at

    files = await ProfileFile.filter(
        profile=profile, created_at__gte=min_date, created_at__lte=max_date,
    ).select_related("bak")

    return [
        file.to_json()
        for file in files
    ]
