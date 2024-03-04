from __future__ import annotations

from tortoise import fields

from ._utils import Model


class Update(Model):
    id: int = fields.BigIntField(pk=True)
    is_base: bool = fields.BooleanField(default=False)
    is_beta: bool = fields.BooleanField(default=False)
    os: str = fields.CharField(max_length=16, default="any")
    arch: str = fields.CharField(max_length=16, default="any")
    files: list[dict[str, str]] = fields.JSONField()
    pending: bool = fields.BooleanField(default=False)
