from datetime import datetime
from typing import Literal, TypeVar

from pydantic import BaseModel, field_validator
from pydantic_core.core_schema import ValidationInfo


class VersionManifestRuleOs(BaseModel):
    name: Literal["linux", "windows", "osx"] | None = None
    arch: Literal["x86"] | None = None  # TODO: more values


class VersionManifestRule(BaseModel):
    action: Literal["allow", "deny"]
    features: dict | None = None
    os: VersionManifestRuleOs | None = None


class VersionManifestArgument(BaseModel):
    rules: list[VersionManifestRule] | None = None
    value: list[str] | str | None = None


class VersionManifestArguments(BaseModel):
    game: list[VersionManifestArgument | str]
    jvm: list[VersionManifestArgument | str]


class VersionManifestLibraryDownloadArtifact(BaseModel):
    path: str | None = None
    sha1: str
    size: int
    url: str


class VersionManifestLibraryDownload(BaseModel):
    artifact: VersionManifestLibraryDownloadArtifact


class VersionManifestLibrary(BaseModel):
    name: str
    url: str | None = None
    rules: list[VersionManifestRule] | None = None
    downloads: VersionManifestLibraryDownload | None = None
    downloadOnly: bool = False


class VersionManifestAssetIndex(BaseModel):
    id: str
    sha1: str
    size: int
    totalSize: int
    url: str


class VersionManifestDownload(BaseModel):
    sha1: str
    size: int
    url: str


class VersionManifestDownloads(BaseModel):
    client: VersionManifestDownload


class VersionManifestJavaVersion(BaseModel):
    component: str
    majorVersion: int


T = TypeVar("T")


class VersionManifest(BaseModel):
    id: str
    inheritsFrom: str | None = None
    time: datetime
    releaseTime: datetime
    type: str
    mainClass: str
    arguments: VersionManifestArguments
    libraries: list[VersionManifestLibrary]

    assets: str | None = None
    assetIndex: VersionManifestAssetIndex | None = None
    downloads: VersionManifestDownloads | None = None
    javaVersion: VersionManifestJavaVersion | None = None

    @field_validator("assets", mode="after")
    @classmethod
    def validate_allow_missing_if_inherits(cls, value: T | None, info: ValidationInfo) -> T | None:
        if info.data["inheritsFrom"] is None and value is None:
            raise ValueError(f"Field required: {info.field_name}")
        return value
