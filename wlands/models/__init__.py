from tortoise.contrib.pydantic import pydantic_model_creator

from .game_profile import GameProfile
from .game_user_session import GameSession
from .join_request import GameJoinRequest
from .player_keypair import PlayerKeyPair
from .player_report import PlayerReport
from .profile_file import ProfileFile, ProfileFileType
from .tg_user import TgUser
from .user import User
from .user_session import UserSession

UserPydantic = pydantic_model_creator(User, exclude=("password",), computed=("has_mfa",))
ProfilePydantic = pydantic_model_creator(
    GameProfile,
    include=("id", "name", "description", "created_at", "updated_at", "public",),
)
ProfileFilePydantic = pydantic_model_creator(
    ProfileFile,
    include=("id", "created_at", "name", "file_id", "sha1", "size"),
    computed=("url", "size_kb_fmt", "_dl"),
)
