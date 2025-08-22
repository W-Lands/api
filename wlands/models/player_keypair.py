from __future__ import annotations

from base64 import b64encode
from datetime import datetime, timedelta
from uuid import UUID

from Crypto.Hash import SHA1
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import PKCS1_v1_5
from pytz import UTC
from tortoise import fields, Model

from wlands import models
from ..config import YGGDRASIL_PRIVATE_KEY


def expires_after_7d():
    return datetime.now().astimezone(UTC) + timedelta(days=7)


def expires_after_6d():
    return datetime.now().astimezone(UTC) + timedelta(days=7)


class PlayerKeyPair(Model):
    id: int = fields.BigIntField(pk=True)
    user: models.User = fields.ForeignKeyField("models.User")
    private_key: str = fields.TextField()
    public_key: str = fields.TextField()
    expires: datetime = fields.DatetimeField(default=expires_after_7d)
    refreshes: datetime = fields.DatetimeField(default=expires_after_6d)
    signature: str = fields.TextField(default="AA==")
    signature_v2: str = fields.TextField()

    user_id: UUID

    @property
    def can_be_refreshed(self) -> bool:
        return datetime.now(self.refreshes.tzinfo) > self.refreshes

    @staticmethod
    def generate_signatures(user: models.User, expires_at_ms: int, pub_key: RsaKey) -> tuple[str, str]:
        signer = PKCS1_v1_5.new(YGGDRASIL_PRIVATE_KEY)
        # TODO: generate signature v1: https://github.com/barneygale/quarry/blob/master/quarry/net/crypto.py#L129
        signature_v2 = signer.sign(SHA1.new(
            user.id.bytes
            + int.to_bytes(expires_at_ms, 8, "big")
            + pub_key.export_key("DER")
        ))
        return "AA==", b64encode(signature_v2).decode("utf8")
