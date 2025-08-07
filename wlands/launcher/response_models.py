from uuid import UUID
from pydantic import BaseModel

from wlands.launcher.manifest_models import VersionManifest
from wlands.models import ProfileFileLoc


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
    location: ProfileFileLoc
    updated_at: int
    download: ProfileFileDownload | None
    delete: bool


class LauncherUpdateInfo(BaseModel):
    version_code: int
    version_name: str
    created_at: int
    repo_url: str
    changelog: str


class LauncherAnnouncementInfo(BaseModel):
    id: int
    name: str
    onetime: bool
    created_at: int
    active_from: int
    active_to: int
    text: str


class AuthlibAgentResponse(BaseModel):
    version: int
    size: int
    sha1: str
    url: str
    min_launcher_version: int
    yggdrasil_pubkey_b64: str


class ProfileIpInfo(BaseModel):
    id: int
    name: str
    ip: str
