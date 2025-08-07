from __future__ import annotations

from datetime import datetime
from enum import IntEnum
from uuid import UUID

from tortoise import fields, Model

from wlands import models
from wlands.config import S3_ENDPOINT_PUBLIC, S3_FILES_BUCKET


class UpdateOs(IntEnum):
    WINDOWS = 1
    LINUX = 2


class LauncherUpdate(Model):
    id: int = fields.BigIntField(pk=True)
    code: int = fields.IntField()
    name: str = fields.CharField(max_length=64)
    created_by: models.User = fields.ForeignKeyField("models.User")
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    size: int = fields.BigIntField()
    changelog: str = fields.TextField()
    os: UpdateOs = fields.IntEnumField(UpdateOs)
    public: bool = fields.BooleanField(default=False)
    dir_id: UUID = fields.UUIDField()

    def to_json(self) -> dict:
        return {
            "version_code": self.code,
            "version_name": self.name,
            "created_at": int(self.created_at.timestamp()),
            "repo_url": f"{S3_ENDPOINT_PUBLIC}/{S3_FILES_BUCKET}/updates/{self.dir_id}",
            "changelog": self.changelog,
        }
