from PIL import Image
from pydantic import BaseModel, Field, EmailStr, field_validator
from pydantic_core.core_schema import ValidationInfo

from wlands.exceptions import CustomBodyException
from wlands.launcher.utils import getImage


class LoginData(BaseModel):
    email: EmailStr
    password: str
    code: str | None = Field(default=None, min_length=6, max_length=6, regex=r'^[0-9]+$')


class TokenRefreshData(BaseModel):
    refresh_token: str


class PatchUserData(BaseModel):
    skin: str | None = Field(default=None, max_length=int(64 * 1024 * 1.5))
    cape: str | None = Field(default=None, max_length=int(64 * 1024 * 1.5))

    @field_validator("skin", "cape")
    def validate_skin_cape(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None or (image := getImage(value)) is None:
            return

        image = Image.open(image)
        if info.field_name == "cape" and image.size != (64, 32):
            raise CustomBodyException(400, {info.field_name: ["Invalid image."]})
        elif info.field_name == "skin" and any(dim != 64 for dim in image.size):
            raise CustomBodyException(400, {info.field_name: ["Invalid image."]})

        return value
