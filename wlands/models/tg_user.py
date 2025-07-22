from tortoise import fields, Model

from wlands import models


class TgUser(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User", on_delete=fields.CASCADE)
