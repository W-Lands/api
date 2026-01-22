from asyncio import get_running_loop
from datetime import datetime, timezone, timedelta
from io import BytesIO
from time import time
from uuid import uuid4

from bcrypt import checkpw
from fastapi import UploadFile, APIRouter
from pytz import UTC
from starlette.responses import RedirectResponse
from tortoise.expressions import Q
from tortoise.transactions import in_transaction

from wlands.config import S3, YGGDRASIL_PUBLIC_STR, S3_ENDPOINT_PUBLIC, S3_FILES_BUCKET, S3_GAME_BUCKET
from wlands.exceptions import CustomBodyException
from wlands.models import LauncherUpdate, UpdateOs
from wlands.models import User, GameSession, GameProfile, ProfileFile, LauncherAnnouncement, AnnouncementOs, \
    AuthlibAgent, ProfileServerAddress, FailedLoginAttempt, FailType, Cape, UserCape
from .dependencies import AuthUserOptDep, AuthUserDep, AuthSessExpDep
from .request_models import LoginData, TokenRefreshData, PatchUserData
from .response_models import AuthResponse, SessionExpirationResponse, UserInfoResponse, ProfileInfo, ProfileFileInfo, \
    LauncherUpdateInfo, LauncherAnnouncementInfo, AuthlibAgentResponse, ProfileIpInfo, CapeInfo
from .utils import Mfa, get_image_from_b64, image_worker, reencode_png

router = APIRouter()


max_attempts_per_time_window_password = [
    (timedelta(minutes=10), 5),
    (timedelta(minutes=30), 10),
    (timedelta(hours=1), 15),
    (timedelta(hours=4), 25),
    (timedelta(hours=6), 30),
    (timedelta(hours=12), 40),
    (timedelta(days=1), 50),
]

max_attempts_per_time_window_mfa = [
    (timedelta(minutes=10), 3),
    (timedelta(minutes=30), 5),
    (timedelta(hours=4), 10),
    (timedelta(hours=12), 15),
    (timedelta(days=1), 20),
]


async def _check_login_attempts_exceeded(user: User) -> bool:
    now = datetime.now(UTC)

    check_mfa_q = Q() if user.mfa_key else Q(type__not=FailType.MFA)
    failed_attempts = await FailedLoginAttempt.filter(
        check_mfa_q, user=user, timestamp__gte=now - timedelta(days=1),
    ).order_by("-timestamp").values_list("type", "timestamp")

    failed_password = 0
    failed_mfa = 0

    for fail_type, timestamp in failed_attempts:
        delta = now - timestamp

        if fail_type is FailType.PASSWORD:
            failed_password += 1
            failed = failed_password
            checks = max_attempts_per_time_window_password
        elif fail_type is FailType.MFA:
            failed_mfa += 1
            failed = failed_mfa
            checks = max_attempts_per_time_window_mfa
        else:
            continue

        for check_delta, attempts in checks:
            if delta < check_delta and failed >= attempts:
                return True

    return False


@router.post("/auth/login", response_model=AuthResponse)
async def login(data: LoginData):
    query = Q(email=data.email) if "@" in data.email else Q(nickname=data.email)
    if (user := await User.get_or_none(query)) is None:
        raise CustomBodyException(400, {"errors": ["User with this email/password does not exists."]})

    if user.banned:
        errors = ["User is banned."]
        if user.ban_reason:
            errors.append(f"Ban reason: {user.ban_reason}")
        raise CustomBodyException(400, {"errors": errors})

    if await _check_login_attempts_exceeded(user):
        raise CustomBodyException(400, {"errors": ["Exceeded maximum number of login requests."]})

    # TODO: check password in thread pool executor?
    if not checkpw(data.password.encode(), user.password.encode()):
        await FailedLoginAttempt.create(user=user, type=FailType.PASSWORD)
        raise CustomBodyException(400, {"errors": ["User with this email/password does not exists."]})

    codes = Mfa.get_codes(user)
    if codes is not None and data.code not in codes:
        await FailedLoginAttempt.create(user=user, type=FailType.MFA)
        raise CustomBodyException(400, {"errors": ["Incorrect 2fa code."]})

    session = await GameSession.create(user=user)

    return {
        "token": session.make_token(),
        "refresh_token": session.make_refresh_token(),
        "expires_at": int(session.expires_at.timestamp()),
    }


@router.post("/auth/refresh", response_model=AuthResponse)
async def refresh_session(data: TokenRefreshData, session: AuthSessExpDep):
    user = session.user

    token_unpacked = GameSession.parse_token(data.refresh_token)
    if token_unpacked is None:
        raise CustomBodyException(400, {"refresh_token": ["Invalid refresh token."]})

    user_id, session_id, refresh_token = token_unpacked

    if session.refresh_token != refresh_token or user_id != user.id or session_id != session.id:
        raise CustomBodyException(400, {"refresh_token": ["Invalid refresh token."]})

    async with in_transaction():
        new_session = await GameSession.create(user=user)
        await session.delete()

    return {
        "token": new_session.make_token(),
        "refresh_token": new_session.make_refresh_token(),
        "expires_at": int(new_session.expires_at.timestamp()),
    }


@router.post("/auth/logout", status_code=204)
async def logout(session: AuthSessExpDep):
    await session.delete()


@router.get("/auth/verify", response_model=SessionExpirationResponse)
async def check_session(session: AuthSessExpDep):
    return {
        "expired": session.expired
    }


@router.get("/users/me", response_model=UserInfoResponse)
@router.get("/users/@me", response_model=UserInfoResponse, deprecated=True)
async def get_me(user: AuthUserDep):
    cape = await user.get_cape()
    return {
        "id": user.id,
        "email": user.email,
        "nickname": user.nickname,
        "skin": user.skin_url,
        "cape": cape.to_json(True, True) if cape is not None else None,
        "mfa": user.mfa_key is not None,
        "admin": user.admin,
    }


async def _edit_cape(user: User, new_cape_id: int) -> None:
    if new_cape_id == 0:
        await UserCape.filter(user=user, selected=True).update(selected=False)
        return

    old_cape = await UserCape.get_or_none(user=user, selected=True)
    if old_cape.cape_id == new_cape_id:
        return

    new_cape = await UserCape.get_or_none(user=user, cape__id=new_cape_id)
    if new_cape is None:
        raise CustomBodyException(400, {"cape_id": ["This cape is not available for you."]})

    old_cape.selected = False
    new_cape.selected = True
    await UserCape.bulk_update([old_cape, new_cape], fields=["selected"])


@router.patch("/users/me", response_model=UserInfoResponse)
@router.patch("/users/@me", response_model=UserInfoResponse, deprecated=True)
async def edit_me(data: PatchUserData, user: AuthUserDep):
    save_fields = []
    if (texture := get_image_from_b64(data.skin)) is not None:
        texture = await get_running_loop().run_in_executor(image_worker, reencode_png, texture)
        user.skin = uuid4()
        await S3.upload_object("wlands", f"skins/{user.id}/{user.skin}.png", texture)
        save_fields.append("skin")
    elif data.skin == "":
        user.skin = None
        save_fields.append("skin")

    async with in_transaction():
        if save_fields:
            await user.save(update_fields=save_fields)

        if data.cape_id is not None:
            await _edit_cape(user, data.cape_id)

    return await get_me(user)


@router.post("/logs", status_code=204)
async def upload_logs(log: UploadFile, user: AuthUserDep, session: str | None = None):
    date = datetime.now(UTC).strftime("%d%m%Y")
    if log.size > 1024 * 1024 * 16:
        return

    if session is None:
        session = time() // 86400

    file = BytesIO(await log.read())
    await S3.upload_object(S3_GAME_BUCKET, f"logs/{date}/{user.id}/{session}/{int(time() % 86400)}.txt", file)


@router.get("/profiles", response_model=list[ProfileInfo])
async def get_profiles(user: AuthUserOptDep, with_manifest: bool = True, only_public: bool = True):
    only_public = only_public or user is None or not user.admin
    profiles_q = Q(public=True) if only_public else Q()

    profiles = await GameProfile.filter(profiles_q).order_by("-updated_at")

    return [
        profile.to_json(with_manifest)
        for profile in profiles
    ]


@router.get("/profiles/{profile_id}/files", response_model=list[ProfileFileInfo])
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

    files = await ProfileFile.filter(profile=profile, created_at__gte=min_date, created_at__lte=max_date)\
        .order_by("created_at")

    return [
        file.to_json()
        for file in files
    ]


@router.get("/updates/latest", response_model=list[LauncherUpdateInfo])
async def get_launcher_latest_update(os: UpdateOs):
    version = await LauncherUpdate.filter(public=True, os=os).last()
    return [version.to_json()] if version else []


@router.get("/updates/latest/repo/{os}/{path:path}")
async def get_launcher_latest_update_redirect(os: UpdateOs, path: str):
    update = await LauncherUpdate.filter(public=True, os=os).last()

    if update is not None:
        url = f"{S3_ENDPOINT_PUBLIC}/{S3_FILES_BUCKET}/updates/{update.dir_id}/{path}"
    else:
        url = "http://unreachable.local"

    return RedirectResponse(url)


@router.get("/announcements", response_model=list[LauncherAnnouncementInfo])
async def get_launcher_announcements(os: AnnouncementOs = AnnouncementOs.ALL):
    now = datetime.now(timezone.utc)

    announcements_q = Q(active_from__lte=now, active_to__gte=now)
    announcements_q &= Q(os=os) | Q(os=AnnouncementOs.ALL)
    announcements = await LauncherAnnouncement.filter(announcements_q)

    return [
        announcement.to_json()
        for announcement in announcements
    ]


@router.get("/authlib-agent", response_model=AuthlibAgentResponse)
async def get_authlib_agent():
    agent = await AuthlibAgent.filter().order_by("-id").first()
    if agent is not None:
        return agent.to_json()

    return {
        "version": 0,
        "size": 0,
        "sha1": "unknown",
        "url": "",
        "min_launcher_version": 0,
        "yggdrasil_pubkey_b64": YGGDRASIL_PUBLIC_STR,
    }


@router.get("/profiles/{profile_id}/ips", response_model=list[ProfileIpInfo])
async def get_profile_ips(profile_id: int, user: AuthUserOptDep):
    if user is None:
        return []

    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise CustomBodyException(404, {"profile_id": ["Unknown profile."]})

    return [
        ip.to_json()
        for ip in await ProfileServerAddress.filter(profile=profile)
    ]


@router.get("/capes", response_model=list[CapeInfo])
async def get_capes(user: AuthUserDep):
    user_cape_ids = set()
    user_cape_sel = None
    for cape_id, selected in await UserCape.filter(user=user).values_list("cape__id", "selected"):
        user_cape_ids.add(cape_id)
        if selected:
            user_cape_sel = cape_id

    capes_query = Cape.filter(Q(public=True) | Q(public=False, id__in=user_cape_ids))

    return [
        cape.to_json(
            available=cape.id in user_cape_ids,
            selected=cape.id == user_cape_sel,
        )
        for cape in await capes_query.order_by("id")
    ]
