from datetime import datetime

from tortoise import Model, fields

from wlands import models
from wlands.config import S3_PUBLIC, YGGDRASIL_PUBLIC_STR


class AuthlibAgent(Model):
    id: int = fields.BigIntField(pk=True)
    created_by: models.User = fields.ForeignKeyField("models.User")
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    size: int = fields.IntField()
    sha1: str = fields.CharField(max_length=64)
    min_launcher_version: int = fields.IntField()
    file_id: str = fields.CharField(max_length=64)

    def url(self) -> str:
        return S3_PUBLIC.share(
            "wlands-profiles", f"authlib-agent/{self.file_id}/{self.sha1}",
            download_filename=f"authlib-agent-{self.id}.jar",
        )

    def to_json(self) -> dict:
        return {
            "version": self.id,
            "size": self.size,
            "sha1": self.sha1,
            "url": self.url(),
            "min_launcher_version": self.min_launcher_version,
            "yggdrasil_pubkey_b64": YGGDRASIL_PUBLIC_STR,
        }
