from __future__ import annotations

from tortoise import fields, Model

from wlands import models


class GameJoinRequest(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User")
    server_id: str = fields.CharField(max_length=64)
