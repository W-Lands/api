from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from uuid import uuid4

from tortoise import fields, Model

from wlands import models
from wlands.config import S3_PUBLIC


class ProfileFileType(IntEnum):
    # <profile_dir> is <game_dir>/profiles/<profile_name>

    # Regular files are placed at <profile_dir>
    PROFILE = 0
    # Regular game files are placed at <game_dir>
    GAME = 1


class ProfileFileBase(Model):
    id: int = fields.BigIntField(pk=True)
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    type: ProfileFileType = fields.IntEnumField(ProfileFileType)
    name: str = fields.TextField()
    sha1: str = fields.CharField(max_length=64)
    size: int = fields.BigIntField()
    file_id: str = fields.CharField(max_length=64, default=lambda: uuid4().hex)
    deleted: bool = fields.BooleanField(default=False)

    class Meta:
        abstract = True

    @property
    def url(self) -> str:
        return S3_PUBLIC.share(
            "wlands-profiles", f"files/{self.file_id}/{self.sha1}", download_filename=self.name.rpartition("/")[2],
        )

    def to_json(self) -> dict:
        download_info = {
            "sha1": self.sha1,
            "size": self.size,
            "url": self.url,
        } if not self.deleted else None

        return {
            "updated_at": int(self.created_at.timestamp()),
            "type": self.type,
            "name": self.name,
            "download": download_info,
            "deleted": self.deleted,
        }


class ProfileFileBak(ProfileFileBase):
    real_id: int = fields.BigIntField(index=True)

    @classmethod
    def from_file(cls, file: ProfileFile) -> ProfileFileBak:
        return ProfileFileBak(
            real_id=file.id,
            created_at=file.created_at,
            type=file.type,
            name=file.name,
            sha1=file.sha1,
            size=file.size,
            file_id=file.file_id,
            deleted=file.deleted,
        )

    @classmethod
    async def bulk_create_and_fill(cls, create: list[ProfileFileBak], fill: list[ProfileFile]) -> None:
        await ProfileFileBak.bulk_create(create)
        baks = {bak.real_id: bak for bak in await ProfileFileBak.filter(real_id__in=[file.id for file in fill])}
        for file in fill:
            file.bak = baks[file.id]


class ProfileFile(ProfileFileBase):
    profile: models.GameProfile = fields.ForeignKeyField("models.GameProfile")
    bak: ProfileFileBak | None = fields.ForeignKeyField("models.ProfileFileBak", null=True, default=None, on_delete=fields.SET_NULL)

    profile_id: int
    bak_id: int | None

    def to_json(self) -> dict:
        if self.bak is not None:
            return self.bak.to_json()
        return super().to_json()
