from __future__ import annotations

from datetime import datetime, timedelta
from os import urandom
from uuid import uuid4, UUID

from tortoise import fields

from wlands import models
from ._utils import Model


def random_hex_64b() -> str:
    return urandom(64).hex()


def expires_after_1d():
    return datetime.now() + timedelta(days=1)


class UserSession(Model):
    id: UUID = fields.UUIDField(pk=True, default=uuid4)
    user: models.User = fields.ForeignKeyField("models.User")
    token: str = fields.CharField(max_length=192, default=random_hex_64b)
    expires_at: datetime = fields.DatetimeField(default=expires_after_1d)
