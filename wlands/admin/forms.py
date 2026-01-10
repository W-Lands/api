from fastapi import UploadFile, File
from pydantic import BaseModel, EmailStr, SecretStr, Field


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
    manifest: UploadFile = File()


class ProfileCreateForm(ProfileInfoForm, ProfileManifestForm):
    ...


class ProfileAddressForm(BaseModel):
    name: str
    address: str


class UploadProfileFilesForm(BaseModel):
    dir_type: str
    dir_prefix: str
    parent: str
    files: list[UploadFile]


class RenameProfileFileForm(BaseModel):
    dir_type: str
    dir_prefix: str
    target_file: str
    target_dir: str
    new_name: str


class DeleteProfileFileForm(BaseModel):
    dir_type: str
    dir_prefix: str
    target_file: str
    target_dir: str
