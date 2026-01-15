from __future__ import annotations

from datetime import datetime
from enum import IntEnum

from tortoise import Model, fields

from wlands import models


class FailType(IntEnum):
    PASSWORD = 0
    MFA = 1


class FailedLoginAttempt(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User")
    type: FailType = fields.IntEnumField(FailType)
    timestamp: datetime = fields.DatetimeField(auto_now_add=True)
    # TODO: add ip
