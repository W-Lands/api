from datetime import datetime
from uuid import UUID

from fastapi import Request

from ..exceptions import ForbiddenException
from ..models.game_user_session import GameSession


async def mc_user_auth_internal(request: Request, from_data: bool):
    if from_data:
        token = (await request.json()).get("accessToken")
    else:
        token = request.headers.get("authorization")
        token = token[7:] if token.startswith("Bearer ") else None

    if not token or len(token) < 96:
        raise ForbiddenException("Invalid token.")

    user_id = UUID(token[:32])
    session_id = UUID(token[32:64])
    session_token = token[64:]

    session = await GameSession.get_or_none(
        id=session_id, user__id=user_id, token=session_token, expires_at__gt=datetime.now()
    ).select_related("user")
    if session is None:
        raise ForbiddenException("Invalid token.")

    return session.user


async def mc_user_auth(request: Request):
    return await mc_user_auth_internal(request, False)


async def mc_user_auth_data(request: Request):
    return await mc_user_auth_internal(request, False)
