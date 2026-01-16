from datetime import datetime, UTC
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Cookie, Request

from ..models import UserSession, User


class NotAuthorized(Exception):
    ...


async def authorize_admin_auth(token: str) -> UserSession:
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
        "expires_at__gt": datetime.now(UTC),
    }
    if (session := await UserSession.get_or_none(**query).select_related("user")) is None:
        raise NotAuthorized

    return session


async def authorize_admin(token: str) -> User:
    session = await authorize_admin_auth(token)
    return session.user


async def admin_auth(auth_token: str = Cookie(default="")) -> User:
    return await authorize_admin(auth_token)


async def admin_opt_auth(auth_token: str = Cookie(default="")) -> User | None:
    try:
        return await authorize_admin(auth_token)
    except NotAuthorized:
        return None


async def admin_opt_auth_session(auth_token: str = Cookie(default="")) -> UserSession | None:
    try:
        return await authorize_admin_auth(auth_token)
    except NotAuthorized:
        return None


AdminSessionMaybe = Annotated[UserSession | None, Depends(admin_opt_auth_session)]
AdminUserDep = Depends(admin_auth)
AdminUserMaybeDep = Depends(admin_opt_auth)
AdminUser = Annotated[User | None, AdminUserDep]
AdminUserMaybe = Annotated[User | None, AdminUserMaybeDep]
