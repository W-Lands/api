from datetime import datetime, UTC
from typing import Annotated
from uuid import UUID

from fastapi import Header, Depends, Cookie

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


async def admin_auth(authorization: str = Header(default="")) -> User:
    return await authorize_admin(authorization)


async def admin_opt_auth(authorization: str = Header(default="")) -> User | None:
    try:
        return await authorize_admin(authorization)
    except NotAuthorized:
        return None


async def admin_auth_new(auth_token: str = Cookie(default="")) -> User:
    return await authorize_admin(auth_token)


async def admin_opt_auth_new(auth_token: str = Cookie(default="")) -> User | None:
    try:
        return await authorize_admin(auth_token)
    except NotAuthorized:
        return None


async def admin_opt_auth_session(auth_token: str = Cookie(default="")) -> UserSession | None:
    try:
        return await authorize_admin_auth(auth_token)
    except NotAuthorized:
        return None


AdminAuthSessionMaybe = Annotated[UserSession | None, Depends(admin_opt_auth_session)]
# TODO: rename everything to AdminUser*
AdminAuthMaybe = Annotated[User | None, Depends(admin_opt_auth)]
AdminAuthNewDep = Depends(admin_auth_new)
AdminAuthMaybeNewDep = Depends(admin_opt_auth_new)
AdminAuthNew = Annotated[User | None, AdminAuthNewDep]
AdminAuthMaybeNew = Annotated[User | None, AdminAuthMaybeNewDep]
