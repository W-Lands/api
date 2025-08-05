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
from .launcher_update import LauncherUpdate, UpdateOs
from .launcher_announcement import LauncherAnnouncement, AnnouncementOs
from .authlib_agent import AuthlibAgent
from .profile_server_address import ProfileServerAddress

UserPydantic = pydantic_model_creator(User, exclude=("password",), computed=("has_mfa",))
ProfilePydantic = pydantic_model_creator(
    GameProfile,
    include=("id", "name", "description", "created_at", "updated_at", "public",),
)
LauncherUpdatePydantic = pydantic_model_creator(
    LauncherUpdate,
    include=("id", "code", "name", "created_at", "sha1", "size", "changelog", "public", "os",), computed=("url",),
)
LauncherAnnouncementPydantic = pydantic_model_creator(
    LauncherAnnouncement,
    include=("id", "name", "onetime", "created_at", "active_from", "active_to", "text", "os",),
)
AuthlibAgentPydantic = pydantic_model_creator(
    AuthlibAgent,
    include=("id", "created_at", "size", "sha1", "min_launcher_version",),
)
ProfileAddress = pydantic_model_creator(
    ProfileServerAddress,
    include=("id", "name", "ip",),
)
