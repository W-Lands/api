from __future__ import annotations

import os.path
from datetime import datetime
from enum import IntEnum
from typing import Self

from tortoise import fields, Model

from wlands import models
from wlands.config import S3_PUBLIC, S3_FILES_BUCKET


class ProfileFileLoc(IntEnum):
    # <profile_dir> is <game_dir>/profiles/<profile_name>

    # Regular files are placed at <profile_dir>
    PROFILE = 0
    # Regular game files are placed at <game_dir>
    GAME = 1


class ProfileFileAction(IntEnum):
    DOWNLOAD = 0
    DELETE = 1


class ProfileFile(Model):
    id: int = fields.BigIntField(pk=True)
    # TODO: use index for either `name` of `parent` ?? or both ???
    name: str = fields.TextField()
    parent: str = fields.TextField()
    profile: models.GameProfile = fields.ForeignKeyField("models.GameProfile")
    created_at: datetime = fields.DatetimeField(auto_now_add=True)
    location: ProfileFileLoc = fields.IntEnumField(ProfileFileLoc)
    action: ProfileFileAction = fields.IntEnumField(ProfileFileAction)

    sha1: str | None = fields.CharField(max_length=64, null=True, default=None)
    size: int | None = fields.BigIntField(null=True, default=None)
    file_id: str | None = fields.CharField(max_length=64, null=True, default=None)

    profile_id: int

    @property
    def url(self) -> str:
        return S3_PUBLIC.share(
            S3_FILES_BUCKET, f"files/{self.file_id}/{self.sha1}", download_filename=self.name.rpartition("/")[2],
        )

    def to_json(self) -> dict:
        download_obj = None
        has_download = self.sha1 is not None and self.size is not None and self.file_id is not None
        if self.action is ProfileFileAction.DOWNLOAD and has_download:
            download_obj = {
                "sha1": self.sha1,
                "size": self.size,
                "url": self.url,
            }

        return {
            "updated_at": int(self.created_at.timestamp()),
            "location": self.location,
            "name": self.name,
            "download": download_obj,
            "delete": self.action is ProfileFileAction.DELETE,
        }

    def clone_delete(self, time_now: datetime) -> Self | None:
        if self.action is ProfileFileAction.DELETE:
            return None
        return ProfileFile(
            name=self.name,
            parent=self.parent,
            profile=self.profile,
            created_at=time_now,
            location=self.location,
            action=ProfileFileAction.DELETE,
            sha1=None,
            size=None,
            file_id=None,
        )

    def clone_rename(self, new_name: str, time_now: datetime) -> Self | None:
        if self.action is ProfileFileAction.DELETE:
            return None
        return ProfileFile(
            name=new_name,
            parent=os.path.dirname(new_name),
            profile=self.profile,
            created_at=time_now,
            location=self.location,
            action=self.action,
            sha1=self.sha1,
            size=self.size,
            file_id=self.file_id,
        )
