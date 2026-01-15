from uuid import uuid4, UUID

from tortoise import fields, Model

from wlands.config import S3_PUBLIC


class Cape(Model):
    id: int = fields.BigIntField(pk=True)
    name: str = fields.CharField(max_length=128)
    file_id: UUID = fields.UUIDField(unique=True, default=uuid4)

    @property
    def url(self) -> str:
        return S3_PUBLIC.share("wlands", f"capes/{self.id}/{self.file_id}.png")
