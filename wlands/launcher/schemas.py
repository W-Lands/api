from PIL import Image
from pydantic import BaseModel, Field, EmailStr, field_validator
from pydantic_core.core_schema import ValidationInfo

from wlands.exceptions import CustomBodyException
from wlands.launcher.utils import getImage


class LoginData(BaseModel):
    email: EmailStr | str
    password: str
    code: str | None = Field(default=None, min_length=6, max_length=6, pattern=r'^[0-9]+$')


class TokenRefreshData(BaseModel):
    refresh_token: str


class PatchUserData(BaseModel):
    skin: str | None = Field(default=None)
    cape: str | None = Field(default=None)

    @field_validator("skin", "cape")
    def validate_skin_cape(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None or value == "":
            return value

        if len(value) > 64 * 1024 * 1.5 or (image := getImage(value)) is None:
            raise CustomBodyException(400, {info.field_name: ["Invalid image."]})

        image = Image.open(image)
        if info.field_name == "cape" and image.size != (64, 32):
            raise CustomBodyException(400, {info.field_name: ["Invalid image."]})
        elif info.field_name == "skin" and any(dim != 64 for dim in image.size):
            raise CustomBodyException(400, {info.field_name: ["Invalid image."]})

        return value


class PresignUrl(BaseModel):
    key: str


class UploadProfileFile(BaseModel):
    path: str
    url: str
    sha1: str


class UploadProfile(BaseModel):
    manifest_url: str
    game_files: list[UploadProfileFile]
    profile_files: list[UploadProfileFile]
    set_current: bool = False
