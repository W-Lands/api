from datetime import datetime
from enum import IntEnum

from tortoise import fields, Model


class AnnouncementOs(IntEnum):
    ALL = 0
    WINDOWS = 1
    LINUX = 2


class LauncherAnnouncement(Model):
    id: int = fields.BigIntField(pk=True)
    name: str = fields.CharField(max_length=64)
    onetime: bool = fields.BooleanField(default=True)
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    active_from: datetime = fields.DatetimeField()
    active_to: datetime = fields.DatetimeField()
    text: str = fields.TextField()
    os: AnnouncementOs = fields.IntEnumField(AnnouncementOs)

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "onetime": self.onetime,
            "created_at": int(self.created_at.timestamp()),
            "active_from": int(self.active_from.timestamp()),
            "active_to": int(self.active_to.timestamp()),
            "text": self.text,
        }
