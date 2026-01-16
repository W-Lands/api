from __future__ import annotations

from tortoise import fields, Model

from wlands import models


class UserCape(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User")
    cape: models.Cape = fields.ForeignKeyField("models.Cape")
    selected: bool = fields.BooleanField(default=False)

    user_id: int
    cape_id: int

    class Meta:
        unique_together = (
            ("user", "cape"),
        )
