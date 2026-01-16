from datetime import datetime
from uuid import uuid4, UUID

from tortoise import fields, Model

from wlands.config import S3_PUBLIC, S3_GAME_BUCKET


class Cape(Model):
    id: int = fields.BigIntField(pk=True)
    name: str = fields.CharField(max_length=128)
    description: str = fields.TextField()
    file_id: UUID = fields.UUIDField(unique=True, default=uuid4)
    public: bool = fields.BooleanField()
    info_public: bool = fields.BooleanField()
    created_at: datetime = fields.DatetimeField(auto_now_add=True)

    @property
    def url(self) -> str:
        return S3_PUBLIC.share(S3_GAME_BUCKET, f"capes/{self.id}/{self.file_id.hex}.png")

    async def to_json(self, available: bool, selected: bool) -> dict:
        info_available = (self.public and self.info_public) or available

        return {
            "id": self.id,
            "name": self.name if info_available else "???",
            "description": self.description if info_available else "???",
            # TODO: use some fallback cape url?
            "url": self.url if info_available else "http://unreachable.local",
            "public": self.public,
            "info_public": self.info_public,
            "created_at": self.created_at,
            "selected": selected,
            "available": available,
        }
