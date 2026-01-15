from datetime import datetime

from fastapi import UploadFile, File
from pydantic import BaseModel, EmailStr, SecretStr

from wlands.models import UpdateOs, AnnouncementOs, ProfileFileLoc


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
    dir_type: ProfileFileLoc
    dir_prefix: str
    parent: str
    files: list[UploadFile]


class RenameProfileFileForm(BaseModel):
    dir_type: ProfileFileLoc
    dir_prefix: str
    target_file: str
    target_dir: str
    new_name: str


class DeleteProfileFileForm(BaseModel):
    dir_type: ProfileFileLoc
    dir_prefix: str
    target_file: str
    target_dir: str


class CreateUpdateForm(BaseModel):
    code: int
    name: str
    changelog: str
    os: UpdateOs
    file: UploadFile


class CreateUpdateAutoForm(BaseModel):
    changelog: str
    file: UploadFile


class UpdateAuthlibForm(BaseModel):
    min_launcher_version: int
    file: UploadFile | None = None


class EditUpdateForm(BaseModel):
    name: str
    changelog: str
    public: bool = False


class CreateAnnouncementForm(BaseModel):
    name: str
    text: str
    os: AnnouncementOs
    onetime: bool = False
    active_from: datetime
    active_to: datetime


class UpdateAnnouncementForm(BaseModel):
    text: str
    onetime: bool = False
    active_from: datetime
    active_to: datetime


class ToggleBanForm(BaseModel):
    reason: str | None = None
