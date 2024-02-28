from pydantic import BaseModel

from wlands.launcher.schemas import PatchUserData


class CreateUser(BaseModel):
    login: str
    email: str
    password: str

    telegram_id: int | None = None


class EditUser(PatchUserData):
    password: str | None = None
    new_password: str | None = None


class CreateUpdate(BaseModel):
    os: str = "any"
    arch: str = "any"
    base: bool = False
