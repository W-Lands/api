from __future__ import annotations

from base64 import b64encode
from datetime import datetime, timedelta

from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from tortoise import fields

from wlands import models
from ._utils import Model
from ..config import YGGDRASIL_PRIVATE_KEY


def expires_after_7d():
    return datetime.now() + timedelta(days=7)


def expires_after_6d():
    return datetime.now() + timedelta(days=7)


class PlayerKeyPair(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User")
    private_key: str = fields.TextField()
    public_key: str = fields.TextField()
    expires: datetime = fields.DatetimeField(default=expires_after_7d)
    refreshes: datetime = fields.DatetimeField(default=expires_after_6d)
    signature: str = fields.TextField(default="AA==")
    signature_v2: str = fields.TextField()

    @property
    def can_be_refreshed(self) -> bool:
        return datetime.now() > self.refreshes

    def generate_signature(self) -> str:
        signer = PKCS1_v1_5.new(YGGDRASIL_PRIVATE_KEY)
        digest = SHA1.new()
        expiresAtMillis = int(self.expires.timestamp() * 1000)
        digest.update(
            self.user.id.bytes +
            int.to_bytes(expiresAtMillis, 8, "big") +
            RSA.importKey(self.public_key).export_key("DER")
        )
        signature = signer.sign(digest)
        return b64encode(signature).decode("utf8")
