from datetime import datetime
from uuid import uuid4, UUID

from tortoise import fields, Model

from wlands.config import S3_PUBLIC, S3_GAME_BUCKET


INVISIBLE_1X1_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="


class Cape(Model):
    id: int = fields.BigIntField(pk=True)
    name: str = fields.CharField(max_length=128)
    description: str = fields.TextField()
    file_id: UUID = fields.UUIDField(unique=True, default=uuid4)
    public: bool = fields.BooleanField()
    info_public: bool = fields.BooleanField()
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    preview: str = fields.TextField(default=INVISIBLE_1X1_PNG_B64)

    @property
    def url(self) -> str:
        return S3_PUBLIC.share(S3_GAME_BUCKET, f"capes/{self.id}/{self.file_id.hex}.png")

    def to_json(self, available: bool, selected: bool) -> dict:
        info_available = (self.public and self.info_public) or available

        return {
            "id": self.id,
            "name": self.name if info_available else "???",
            "description": self.description if info_available else "???",
            # TODO: use some fallback cape url?
            "url": self.url if info_available else "http://unreachable.local",
            "preview": self.preview if info_available else INVISIBLE_1X1_PNG_B64,
            "public": self.public,
            "info_public": self.info_public,
            "created_at": int(self.created_at.timestamp()),
            "selected": selected,
            "available": available,
        }
