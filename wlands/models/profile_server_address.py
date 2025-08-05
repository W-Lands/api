from __future__ import annotations
from tortoise import fields, Model

from wlands import models


class ProfileServerAddress(Model):
    id: int = fields.BigIntField(pk=True)
    profile: models.GameProfile = fields.ForeignKeyField("models.GameProfile")
    name: str = fields.CharField(max_length=128)
    ip: str = fields.CharField(max_length=64)

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "ip": self.ip,
        }
