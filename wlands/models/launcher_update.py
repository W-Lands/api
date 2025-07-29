from __future__ import annotations

from datetime import datetime
from enum import IntEnum

from tortoise import fields, Model

from wlands import models
from wlands.config import S3_PUBLIC


class UpdateOs(IntEnum):
    WINDOWS = 1
    LINUX = 2


class LauncherUpdate(Model):
    id: int = fields.BigIntField(pk=True)
    name: str = fields.CharField(max_length=64)
    created_by: models.User = fields.ForeignKeyField("models.User")
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    sha1: str = fields.CharField(max_length=64)
    size: int = fields.BigIntField()
    changelog: str = fields.TextField()
    os: UpdateOs = fields.IntEnumField(UpdateOs)
    public: bool = fields.BooleanField(default=False)

    def url(self) -> str:
        return S3_PUBLIC.share(
            "wlands-profiles", f"updates/{self.sha1}", download_filename=f"WLands-{self.name}-{self.id}.msi",
        )

    def to_json(self) -> dict:
        return {
            "version_code": self.id,
            "version_name": self.name,
            "created_at": int(self.created_at.timestamp()),
            "url": self.url(),
            "sha1": self.sha1,
            "size": self.size,
            "changelog": self.changelog,
        }
