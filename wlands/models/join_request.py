from tortoise import fields

from wlands import models
from ._utils import Model


class GameJoinRequest(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User")
    server_id: str = fields.CharField(max_length=64)
