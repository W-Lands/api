from tortoise.contrib.pydantic import pydantic_model_creator

from .game_profile import GameProfile
from .game_user_session import GameSession
from .join_request import GameJoinRequest
from .player_keypair import PlayerKeyPair
from .player_report import PlayerReport
from .profile_file import ProfileFile, ProfileFileLoc, ProfileFileAction
from .tg_user import TgUser
from .user import User
from .user_session import UserSession
from .launcher_update import LauncherUpdate
from .launcher_announcement import LauncherAnnouncement

UserPydantic = pydantic_model_creator(User, exclude=("password",), computed=("has_mfa",))
ProfilePydantic = pydantic_model_creator(
    GameProfile,
    include=("id", "name", "description", "created_at", "updated_at", "public",),
)
