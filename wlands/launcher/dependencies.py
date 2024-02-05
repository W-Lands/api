from datetime import datetime
from uuid import UUID

from fastapi import Request

from ..exceptions import ForbiddenException
from ..models.game_user_session import GameSession


async def get_session(request: Request, allow_expired: bool):
    token = request.headers.get("authorization")

    if not token or len(token) < 96:
        raise ForbiddenException("Invalid token.")

    user_id = UUID(token[:32])
    session_id = UUID(token[32:64])
    session_token = token[64:]

    q = {"id": session_id, "user__id": user_id, "token": session_token}
    if not allow_expired:
        q["expires_at__gt"] = datetime.utcnow()
    if (session := await GameSession.get_or_none(**q).select_related("user")) is None:
        raise ForbiddenException("Invalid token.")

    return session


async def sess_auth(request: Request):
    return await get_session(request, False)


async def sess_auth_expired(request: Request):
    return await get_session(request, True)


async def user_auth(request: Request):
    return (await get_session(request, False)).user


async def user_auth_expired(request: Request):
    return (await get_session(request, True)).user
