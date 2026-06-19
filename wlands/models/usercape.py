from __future__ import annotations

from uuid import UUID

from tortoise import fields, Model

from wlands import models


class UserCape(Model):
    id: int = fields.BigIntField(primary_key=True)
    user: models.User = fields.ForeignKeyField("models.User")
    cape: models.Cape = fields.ForeignKeyField("models.Cape")
    selected: bool = fields.BooleanField(default=False)

    user_id: UUID
    cape_id: int

    class Meta:
        unique_together = (
            ("user", "cape"),
        )
