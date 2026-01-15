from __future__ import annotations

from datetime import datetime, timedelta, UTC
from os import urandom
from uuid import UUID, uuid4

from tortoise import fields, Model

from wlands import models


def random_hex_64b() -> str:
    return urandom(64).hex()


def expires_after_7d():
    return datetime.now(UTC) + timedelta(days=7)


class GameSession(Model):
    id: UUID = fields.UUIDField(pk=True, default=uuid4)
    user: models.User = fields.ForeignKeyField("models.User")
    token: str = fields.CharField(max_length=192, default=random_hex_64b)
    refresh_token: str = fields.CharField(max_length=192, default=random_hex_64b)
    expires_at: datetime = fields.DatetimeField(default=expires_after_7d)

    @property
    def expired(self) -> bool:
        return datetime.now(self.expires_at.tzinfo) > self.expires_at
