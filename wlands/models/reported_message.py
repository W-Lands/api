from __future__ import annotations

from datetime import datetime

from tortoise import fields, Model

from wlands import models


class ReportMessage(Model):
    id: int = fields.BigIntField(pk=True)
    report: models.PlayerReport = fields.ForeignKeyField("models.PlayerReport")
    user: models.User = fields.ForeignKeyField("models.User")
    date: datetime = fields.DatetimeField()
    text: str = fields.TextField()
    reported: bool = fields.BooleanField()
