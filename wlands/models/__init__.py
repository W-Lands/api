from tortoise.contrib.pydantic import pydantic_model_creator

from .allowed_mod import AllowedMod
from .game_user_session import GameSession
from .join_request import GameJoinRequest
from .player_keypair import PlayerKeyPair
from .player_report import PlayerReport
from .tg_user import TgUser
from .update import Update
from .user import User
from .user_session import UserSession

UserPydantic = pydantic_model_creator(User, exclude=("password",), computed=("has_mfa",))
