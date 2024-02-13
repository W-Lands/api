from tortoise import fields

from wlands import models
from wlands.models._utils import Model


class TgUser(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User", on_delete=fields.CASCADE)
