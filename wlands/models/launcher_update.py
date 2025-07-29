from datetime import datetime

from tortoise import fields, Model

from wlands.config import S3_PUBLIC


class LauncherUpdate(Model):
    id: int = fields.BigIntField(pk=True)
    name: str = fields.CharField(max_length=64)
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    sha1: str = fields.CharField(max_length=64)
    size: int = fields.BigIntField()
    changelog: str = fields.TextField()

    def to_json(self) -> dict:
        return {
            "version_code": self.id,
            "version_name": self.name,
            "created_at": int(self.created_at.timestamp()),
            "url": S3_PUBLIC.share(
                "wlands-profiles", f"updates/{self.id}/{self.sha1}", download_filename=f"WLands-{self.name}.msi",
            ),
            "sha1": self.sha1,
            "size": self.size,
            "changelog": self.changelog,
        }
