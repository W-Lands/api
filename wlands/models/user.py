from __future__ import annotations

import json
from base64 import b64encode
from time import time
from uuid import uuid4, UUID

from Crypto.Hash import SHA1
from Crypto.Signature import PKCS1_v1_5
from tortoise import fields

from ._utils import Model
from ..config import S3, YGGDRASIL_PRIVATE_KEY


class User(Model):
    id: UUID = fields.UUIDField(pk=True, default=uuid4)
    email: str = fields.CharField(max_length=255, unique=True)
    nickname: str = fields.CharField(max_length=32, unique=True)
    password: str = fields.TextField()
    skin: str = fields.UUIDField(null=True, default=None)
    cape: str = fields.UUIDField(null=True, default=None)
    mfa_key: str = fields.CharField(null=True, default=None, max_length=64)
    signed_for_beta: bool = fields.BooleanField(default=False)
    banned: bool = fields.BooleanField(default=False)
    admin: bool = fields.BooleanField(default=False)

    @property
    def skin_url(self) -> str | None:
        if self.skin is None:
            return None
        return S3.share("wlands", f"skins/{self.id}/{self.skin}.png")

    @property
    def cape_url(self) -> str | None:
        if self.cape is None:
            return None
        return S3.share("wlands", f"capes/{self.id}/{self.cape}.png")

    def properties(self, signed: bool = False) -> list[dict[str, str]]:
        props = []
        if not self.skin_url and not self.cape_url:
            return props
        actual_textures = {}
        if self.skin_url:
            actual_textures["SKIN"] = {"url": self.skin_url}
        if self.cape_url:
            actual_textures["CAPE"] = {"url": self.cape_url}
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
        props.append(textures)

        return props
