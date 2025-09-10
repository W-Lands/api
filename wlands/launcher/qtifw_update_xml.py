from pydantic_xml import BaseXmlModel, element, attr
from pydantic_xml.element import SearchMode


class UpdateFile(BaseXmlModel):
    __xml_search_mode__ = SearchMode.UNORDERED

    compressed_size: int = attr(name="CompressedSize")
    uncompressed_size: int = attr(name="UncompressedSize")
    os: str = attr(name="OS")


class PackageUpdate(BaseXmlModel):
    __xml_search_mode__ = SearchMode.UNORDERED

    name: str = element(tag="Name")
    display_name: str = element(tag="DisplayName")
    description: str = element(tag="Description", default="")
    version: str = element(tag="Version")
    release_date: str = element(tag="ReleaseDate")
    forced_installation: bool = element(tag="ForcedInstallation")
    default: bool = element(tag="Default", default=False)
    update_file: UpdateFile = element(tag="UpdateFile")
    downloadable_archives: str = element(tag="DownloadableArchives")
    sha1: str = element(tag="SHA1")


class Updates(BaseXmlModel):
    __xml_search_mode__ = SearchMode.UNORDERED

    application_name: str = element(tag="ApplicationName")
    application_version: str = element(tag="ApplicationVersion")
    checksum: bool = element(tag="Checksum")
    package_updates: list[PackageUpdate] = element(tag="PackageUpdate")
    sha1: str = element(tag="SHA1")
    metadata_name: str = element(tag="MetadataName")
