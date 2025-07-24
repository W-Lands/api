from datetime import datetime
from uuid import UUID

from fastapi import Header

from ..models import UserSession, User


class NotAuthorized(Exception):
    ...


async def authorize_admin(token: str) -> User:
    if token.startswith("Token "):
        token = token[6:]
    if not token or len(token) < 96:
        raise NotAuthorized

    user_id = UUID(token[:32])
    session_id = UUID(token[32:64])
    session_token = token[64:]

    query = {
        "id": session_id,
        "user__id": user_id,
        "token": session_token,
        "user__banned": False,
        "user__admin": True,
        "expires_at__gt": datetime.utcnow(),
    }
    if (session := await UserSession.get_or_none(**query).select_related("user")) is None:
        raise NotAuthorized

    return session.user


async def admin_auth(authorization: str = Header(default="")) -> User:
    return await authorize_admin(authorization)


async def admin_opt_auth(authorization: str = Header(default="")) -> User | None:
    try:
        return await authorize_admin(authorization)
    except NotAuthorized:
        return
