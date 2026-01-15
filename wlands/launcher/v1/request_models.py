from PIL import Image
from pydantic import BaseModel, Field, EmailStr, field_validator
from pydantic_core.core_schema import ValidationInfo

from wlands.exceptions import CustomBodyException
from .utils import get_image_from_b64


class LoginData(BaseModel):
    email: EmailStr | str
    password: str
    code: str | None = Field(default=None, min_length=6, max_length=6, pattern=r'^[0-9]+$')


class TokenRefreshData(BaseModel):
    refresh_token: str


class PatchUserData(BaseModel):
    skin: str | None = Field(default=None)

    @field_validator("skin")
    def validate_skin(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None or value == "":
            return value

        if len(value) > 64 * 1024 * 1.5 or (image := get_image_from_b64(value)) is None:
            raise CustomBodyException(400, {info.field_name: ["Invalid image."]})

        image = Image.open(image)
        if any(dim != 64 for dim in image.size):
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
