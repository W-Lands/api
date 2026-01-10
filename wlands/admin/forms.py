from fastapi import UploadFile
from fastui.forms import FormFile
from pydantic import BaseModel, EmailStr, SecretStr


class LoginForm(BaseModel):
    email: EmailStr
    password: SecretStr


class UserCreateForm(BaseModel):
    nickname: str
    password: SecretStr


class ProfileInfoForm(BaseModel):
    name: str
    description: str
    public: bool = False
    
    
class ProfileManifestForm(BaseModel):
    manifest: UploadFile = FormFile(accept="application/json,.json", max_size=256 * 1024)


class ProfileCreateForm(ProfileInfoForm, ProfileManifestForm):
    ...


class ProfileAddressForm(BaseModel):
    name: str
    address: str
