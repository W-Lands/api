from pydantic import BaseModel

from wlands.models import ProfileFileType


class AuthResponse(BaseModel):
    token: str
    refresh_token: str
    expires_at: int


class SessionExpirationResponse(BaseModel):
    expired: bool


class UserInfoResponse(BaseModel):
    id: int
    email: str
    nickname: str
    skin: str | None
    cape: str | None
    mfa: bool
    admin: bool


class ProfileInfo(BaseModel):
    id: int
    name: str
    description: str
    created_at: int
    updated_at: int
    version_manifest: dict | None  # TODO: type annotate manifest


class ProfileFileInfo(BaseModel):
    name: str
    type: ProfileFileType
    created_at: int
    sha1: str
    url: str
