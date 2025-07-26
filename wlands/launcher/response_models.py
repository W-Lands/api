from uuid import UUID
from pydantic import BaseModel

from wlands.launcher.manifest_models import VersionManifest
from wlands.models import ProfileFileType


class AuthResponse(BaseModel):
    token: str
    refresh_token: str
    expires_at: int


class SessionExpirationResponse(BaseModel):
    expired: bool


class UserInfoResponse(BaseModel):
    id: UUID
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
    version_manifest: VersionManifest | None
    public: bool


class ProfileFileDownload(BaseModel):
    sha1: str
    url: str
    size: int


class ProfileFileInfo(BaseModel):
    name: str
    type: ProfileFileType
    updated_at: int
    download: ProfileFileDownload | None
    deleted: bool
