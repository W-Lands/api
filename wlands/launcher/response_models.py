from pydantic import BaseModel


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
