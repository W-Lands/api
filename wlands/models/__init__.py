from tortoise.contrib.pydantic import pydantic_model_creator

from .game_user_session import GameSession
from .join_request import GameJoinRequest
from .player_keypair import PlayerKeyPair
from .player_report import PlayerReport
from .user import User
from .user_session import UserSession
from .update import Update
from .tg_user import TgUser
from .allowed_mod import AllowedMod


UserPydantic = pydantic_model_creator(User, exclude=("password",), computed=("has_mfa",))
