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


class ProfileFile(Model):
    id: int = fields.BigIntField(pk=True)
    profile: models.GameProfile = fields.ForeignKeyField("models.GameProfile")
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    type: ProfileFileType = fields.IntEnumField(ProfileFileType)
    name: str = fields.TextField()
    sha1: str = fields.CharField(max_length=64)
    size: int = fields.BigIntField()
    file_id: str = fields.CharField(max_length=64, default=lambda: uuid4().hex)
    deleted: bool = fields.BooleanField(default=False)

    def _dl(self) -> str:
        return "Download"

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
