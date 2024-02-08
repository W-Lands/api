from __future__ import annotations

from tortoise import fields

from wlands import models
from ._utils import Model


class PlayerReport(Model):
    id: int = fields.BigIntField(pk=True)
    reporter: models.User = fields.ForeignKeyField("models.User", related_name="reporter")
    reporter_client: str = fields.CharField(max_length=32)
    reported: models.User = fields.ForeignKeyField("models.User", related_name="reported")
    comment: str = fields.TextField(max_length=1024)
    reason: int = fields.IntField()
    messages: list = fields.JSONField()
    server_address: str = fields.CharField(max_length=128)
