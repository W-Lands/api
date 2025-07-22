from __future__ import annotations

from tortoise import fields, Model


class AllowedMod(Model):
    id: int = fields.CharField(pk=True, max_length=128)
    description: str = fields.CharField(max_length=128)
    hashed_id = fields.CharField(max_length=64)
    classes: list[str] = fields.JSONField(default=[])
