from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from uuid import uuid4

from tortoise import fields, Model

from wlands import models
from wlands.config import S3


class ProfileFileType(IntEnum):
    # <profile_dir> is <game_dir>/profiles/<profile_name>

    # Regular files are placed at <profile_dir>
    REGULAR = 0
    # Regular game files are placed at <game_dir>
    REGULAR_GAME = 1
    # Libraries are placed at <game_dir>/libraries
    LIBRARY = 2
    # Assets are placed at <game_dir>/assets
    ASSET = 3


class ProfileFile(Model):
    id: int = fields.BigIntField(pk=True)
    profile: models.GameProfile = fields.ForeignKeyField("models.GameProfile")
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    type: ProfileFileType = fields.IntEnumField(ProfileFileType)
    name: str = fields.TextField()
    sha1: str = fields.CharField(max_length=64)
    file_id: str = fields.CharField(max_length=64, default=lambda: uuid4().hex)
    # TODO: deleted

    def to_json(self) -> dict:
        return {
            "created_at": int(self.created_at.timestamp()),
            "type": self.type,
            "name": self.name,
            "sha1": self.sha1,
            "url": S3.share("wlands-profiles", f"files/{self.id}/{self.file_id}"),
        }
