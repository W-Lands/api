from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import Request, Depends
from pytz import UTC

from wlands.exceptions import ForbiddenException
from wlands.models import User, GameSession


async def get_session(request: Request, allow_expired: bool) -> GameSession:
    token = request.headers.get("authorization")

    if not token or len(token) < 96:
        raise ForbiddenException("Invalid token.")

    user_id = UUID(token[:32])
    session_id = UUID(token[32:64])
    session_token = token[64:]

    q = {"id": session_id, "user__id": user_id, "token": session_token}
    if not allow_expired:
        q["expires_at__gt"] = datetime.now(UTC)
    if (session := await GameSession.get_or_none(**q).select_related("user")) is None:
        raise ForbiddenException("Invalid token.")

    if session.user.banned:
        raise ForbiddenException("User is banned.")

    return session


async def sess_auth(request: Request) -> GameSession:
    return await get_session(request, False)


async def sess_auth_expired(request: Request) -> GameSession:
    return await get_session(request, True)


async def user_auth(request: Request) -> User:
    session = await sess_auth(request)
    return session.user


async def user_auth_expired(request: Request) -> User:
    session = await sess_auth_expired(request)
    return session.user


async def user_auth_maybe(request: Request) -> User | None:
    try:
        session = await sess_auth(request)
    except ForbiddenException:
        return None
    else:
        return session.user


AuthSessDep = Annotated[GameSession, Depends(sess_auth)]
AuthSessExpDep = Annotated[GameSession, Depends(sess_auth_expired)]
AuthUserDep = Annotated[User, Depends(user_auth)]
AuthUserExpDep = Annotated[User, Depends(user_auth_expired)]
AuthUserOptDep = Annotated[User | None, Depends(user_auth_maybe)]
