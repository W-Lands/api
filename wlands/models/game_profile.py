from __future__ import annotations

from datetime import datetime

from tortoise import fields, Model

from wlands import models


class GameProfile(Model):
    id: int = fields.BigIntField(pk=True)
    name: str = fields.CharField(max_length=128, unique=True)
    description: str = fields.TextField()
    creator: models.User | None = fields.ForeignKeyField("models.User", null=True, on_delete=fields.SET_NULL)
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    updated_at: datetime = fields.DatetimeField(auto_now_add=True)
    version_manifest: dict = fields.JSONField()
    public: bool = fields.BooleanField(default=False)

    def to_json(self, with_manifest: bool) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": int(self.created_at.timestamp()),
            "updated_at": int(self.updated_at.timestamp()),
            "version_manifest": self.version_manifest if with_manifest else None,
            "public": self.public,
        }
