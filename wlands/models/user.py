from __future__ import annotations

import json
from base64 import b64encode
from datetime import datetime
from time import time
from uuid import uuid4, UUID

from Crypto.Hash import SHA1
from Crypto.Signature import PKCS1_v1_5
from tortoise import fields, Model

from .. import models
from ..config import S3_PUBLIC, YGGDRASIL_PRIVATE_KEY


class User(Model):
    id: UUID = fields.UUIDField(pk=True, default=uuid4)
    email: str = fields.CharField(max_length=255, unique=True)
    nickname: str = fields.CharField(max_length=32, unique=True)
    password: str = fields.TextField()
    skin: str | None = fields.UUIDField(null=True, default=None)
    mfa_key: str | None = fields.CharField(null=True, default=None, max_length=64)
    banned: bool = fields.BooleanField(default=False)
    ban_reason: str | None = fields.TextField(null=True, default=None)
    admin: bool = fields.BooleanField(default=False)
    created_at: datetime = fields.DatetimeField(auto_now_add=True)

    @property
    def skin_url(self) -> str | None:
        if self.skin is None:
            return None
        return S3_PUBLIC.share("wlands", f"skins/{self.id}/{self.skin}.png")

    def properties(self, signed: bool = False, cape: models.Cape | None = None) -> list[dict[str, str]]:
        if not self.skin_url and not cape:
            return []

        actual_textures = {}
        if self.skin_url:
            actual_textures["SKIN"] = {"url": self.skin_url}
        if cape:
            actual_textures["CAPE"] = {"url": cape.url}

        textures = {
            "name": "textures",
            "value": b64encode(json.dumps({
                "timestamp": int(time() * 1000),
                "profileId": self.id.hex,
                "profileName": self.nickname,
                "signatureRequired": signed,
                "textures": actual_textures
            }).encode("utf8")).decode("utf8")
        }

        if signed:
            signer = PKCS1_v1_5.new(YGGDRASIL_PRIVATE_KEY)
            digest = SHA1.new()
            digest.update(textures["value"].encode("utf8"))
            signature = signer.sign(digest)
            textures["signature"] = b64encode(signature).decode("utf8")

        return [textures]

    async def get_cape(self) -> models.Cape | None:
        return await models.Cape.get_or_none(usercape__user=self, usercape__selected=True)

