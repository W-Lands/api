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


class Update(Model):
    id: int = fields.BigIntField(pk=True)
    is_base: bool = fields.BooleanField(default=False)
    is_beta: bool = fields.BooleanField(default=False)
    os: str = fields.CharField(max_length=16, default="any")
    arch: str = fields.CharField(max_length=16, default="any")
    files: list[dict[str, str]] = fields.JSONField()
    pending: bool = fields.BooleanField(default=False)
