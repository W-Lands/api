from tortoise.contrib.pydantic import pydantic_model_creator

from .game_user_session import GameSession
from .join_request import GameJoinRequest
from .player_keypair import PlayerKeyPair
from .player_report import PlayerReport
from .tg_user import TgUser
from .user import User
from .user_session import UserSession
from .game_profile import GameProfile
from .profile_file import ProfileFile, ProfileFileType

UserPydantic = pydantic_model_creator(User, exclude=("password",), computed=("has_mfa",))
