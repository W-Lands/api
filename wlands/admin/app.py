import json
import os
from asyncio import sleep
from datetime import datetime, timezone
from hashlib import sha1
from pathlib import Path
from uuid import UUID, uuid4
from zipfile import ZipFile

from bcrypt import checkpw, hashpw, gensalt
from fastapi import Request, HTTPException, Form, APIRouter
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel
from pytz import UTC
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.templating import Jinja2Templates
from tortoise.expressions import Q
from tortoise.transactions import in_transaction

from wlands.admin.dependencies import AdminUserMaybe, AdminUser, AdminUserDep, AdminSessionMaybe
from wlands.admin.forms import LoginForm, UserCreateForm, ProfileCreateForm, ProfileInfoForm, ProfileManifestForm, \
    ProfileAddressForm, UploadProfileFilesForm, RenameProfileFileForm, DeleteProfileFileForm, CreateUpdateForm, \
    CreateUpdateAutoForm, UpdateAuthlibForm, EditUpdateForm, CreateAnnouncementForm, UpdateAnnouncementForm, \
    ToggleBanForm, CreateCapeForm, CapeInfoForm
from wlands.admin.jinja_filters import format_size, format_enum, format_bool, format_datetime
from wlands.config import S3, S3_FILES_BUCKET, S3_GAME_BUCKET
from wlands.common.manifest_models import VersionManifest
from wlands.common.qtifw_update_xml import Updates
from wlands.models import User, UserSession, GameSession, GameProfile, ProfileFile, ProfileFileLoc, ProfileFileAction, \
    LauncherUpdate, UpdateOs, LauncherAnnouncement, AnnouncementOs, AuthlibAgent, ProfileServerAddress, Cape


router = APIRouter(prefix="/admin")
templates_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=True,
)
templates = Jinja2Templates(env=templates_env)
templates_env.filters["format_size"] = format_size
templates_env.filters["format_enum"] = format_enum
templates_env.filters["format_bool"] = format_bool
templates_env.filters["format_datetime"] = format_datetime


class ProfileRootDir(BaseModel):
    name: str
    type: ProfileFileLoc


class ProfileFileF(BaseModel):
    name: str
    id: int | None = None
    created_at: datetime | None = None
    sha1: str | None = None
    size: int | None = None
    url: str | None = None
    fake: bool = False


class UnappliedProfileFile(BaseModel):
    root: str
    path: str
    created: bool = False
    deleted: bool = False


class Pagination:
    def __init__(self, page: int, page_size: int, total: int, add_pages_num: int = 2) -> None:
        self.page = page
        self.page_size = page_size
        self.total = total
        self.total_pages = (total + page_size - 1) // page_size
        self.has_prev = self.page > 1
        self.has_next = self.page < self.total_pages
        self.page_offset = page_size * (page - 1)
        self.next_page_offset = min(total, page_size * page)
        self.pages: list[int | None] = [
            p
            for p in range(page - add_pages_num, page + add_pages_num + 1)
            if 1 <= p <= self.total_pages
        ]

        if not self.pages:
            self.pages.append(1)

        if self.pages[0] != 1:
            if self.pages[0] != 2:
                self.pages.insert(0, None)
            self.pages.insert(0, 1)

        if self.total_pages > 0 and self.pages[-1] != self.total_pages:
            if self.pages[-1] != (self.total_pages - 1):
                self.pages.append(None)
            self.pages.append(self.total_pages)


profile_root_dirs: dict[ProfileFileLoc, ProfileRootDir] = {
    ProfileFileLoc.GAME: ProfileRootDir(
        name="<Game Directory>",
        type=ProfileFileLoc.GAME,
    ),
    ProfileFileLoc.PROFILE: ProfileRootDir(
        name="<Profile Directory>",
        type=ProfileFileLoc.PROFILE,
    ),
}


@router.get("/login", response_class=HTMLResponse)
def admin_login_page(user: AdminUserMaybe, request: Request):
    if user is not None:
        return RedirectResponse(request.url_for("admin_users_page"))

    return templates.TemplateResponse(request=request, name="login.jinja2")


@router.get("/logout")
async def admin_logout_page(request: Request, session: AdminSessionMaybe):
    if session is not None:
        await session.delete()

    resp = RedirectResponse(request.url_for("admin_login_page"), 303)
    resp.delete_cookie("auth_token")
    return resp


@router.post("/login", response_class=HTMLResponse)
async def admin_login(user: AdminUserMaybe, request: Request, form: LoginForm = Form()):
    if user is not None:
        return RedirectResponse(request.url_for("admin_users_page"))

    error_resp = templates.TemplateResponse(request=request, name="login.jinja2", context={
        "error": "Wrong credentials."
    })

    if (user := await User.get_or_none(email=form.email, admin=True, banned=False)) is None:
        return error_resp
    if not checkpw(form.password.get_secret_value().encode(), user.password.encode()):
        return error_resp

    # TODO: also check mfa

    session = await UserSession.create(user=user)

    resp = RedirectResponse(request.url_for("admin_users_page"), 303)
    resp.set_cookie(
        "auth_token", f"{user.id.hex}{session.id.hex}{session.token}", expires=int(session.expires_at.timestamp())
    )
    return resp


async def _users_page(request: Request, page: int, create_error: str | None = None, create_nickname: str = ""):
    PAGE_SIZE = 25

    users = await User.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("created_at")
    total = await User.all().count()

    return templates.TemplateResponse(request=request, name="users.jinja2", context={
        "pagination": Pagination(page, PAGE_SIZE, total),
        "users": users,
        "error": create_error,
        "show_create_modal": bool(create_error),
        "create_form_nickname": create_nickname,
    })


@router.get("/users", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_users_page(request: Request, page: int = 1):
    return await _users_page(request, page)


@router.post("/users", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_create_user(request: Request, form: UserCreateForm = Form()):
    if await User.filter(nickname=form.nickname).exists():
        return await _users_page(request, 1, "User with this nickname already exists.", form.nickname)

    new_user = await User.create(
        email=f"{form.nickname}@wlands.pepega",
        nickname=form.nickname,
        password=hashpw(form.password.get_secret_value().encode("utf8"), gensalt()).decode("utf8"),
    )

    return RedirectResponse(request.url_for("admin_users_page", user_id=new_user.id), 303)


@router.get("/users/{user_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_user_info_page(request: Request, user_id: UUID):
    target = await User.get_or_none(id=user_id)
    return templates.TemplateResponse(request=request, name="user.jinja2", context={
        "user": target,
    })


@router.post("/users/{user_id}/toggle-ban", response_class=HTMLResponse)
async def admin_ban_unban_user(request: Request, user_id: UUID, admin: AdminUser, form: ToggleBanForm = Form()):
    if (target := await User.get_or_none(id=user_id)) is None:
        return RedirectResponse(request.url_for("admin_users_page"), 303)
    if target.id == admin.id or target.admin:
        return templates.TemplateResponse(request=request, name="user.jinja2", context={
            "user": target,
            "ban_error": "You can't ban this user",
        })

    target.banned = not target.banned
    target.ban_reason = form.reason if target.banned else None
    if target.banned:
        await GameSession.filter(user=target).delete()
        await UserSession.filter(user=target).delete()

    await target.save(update_fields=["banned", "ban_reason"])

    return RedirectResponse(request.url_for("admin_users_page", user_id=target.id), 303)


@router.post("/users/{user_id}", response_class=HTMLResponse)
async def admin_edit_user(request: Request, user_id: UUID, admin: AdminUser, nickname: str = Form()):
    if (target := await User.get_or_none(id=user_id)) is None:
        return RedirectResponse(request.url_for("admin_users_page"), 303)
    if target.id == admin.id or target.admin:
        return templates.TemplateResponse(request=request, name="user.jinja2", context={
            "user": target,
            "edit_error": "You can't edit this user",
            "edit_form_nickname": nickname,
        })

    if await User.filter(nickname=nickname).exists():
        return templates.TemplateResponse(request=request, name="user.jinja2", context={
            "user": target,
            "edit_error": "User with this nickname already exists.",
            "edit_form_nickname": nickname,
        })

    target.nickname = nickname
    target.email = f"{nickname}@wlands.pepega"
    await target.save(update_fields=["nickname", "email"])

    return RedirectResponse(request.url_for("admin_users_page", user_id=target.id), 303)


@router.get("/profiles", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_profiles_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    profiles = await GameProfile.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("id")
    total = await GameProfile.all().count()

    return templates.TemplateResponse(request=request, name="profiles.jinja2", context={
        "profiles": profiles,
        "pagination": Pagination(page, PAGE_SIZE, total),
    })


async def _get_profile_files(profile: GameProfile, root: ProfileRootDir, prefix: str) -> list[ProfileFileF]:
    files = await ProfileFile.filter(
        profile=profile, location=root.type, parent__startswith=prefix,
    ).order_by("-created_at")

    vdirs = {}
    vfiles = []
    seen_files = set()

    for file in files:
        file_path = file.name[len(prefix):].lstrip("/")
        if file_path in seen_files:
            continue

        seen_files.add(file_path)
        if file.action is ProfileFileAction.DELETE:
            continue

        name, maybe_slash, _ = file_path.partition("/")
        if maybe_slash:
            vdir = vdirs.get(name)
            if vdir is None:
                name = f"{name}/"
                vdirs[name] = vdir = ProfileFileF(name=name, size=0)

            vdir.size += file.size
            continue

        vfiles.append(ProfileFileF(
            name=name,
            id=file.id,
            created_at=file.created_at,
            sha1=file.sha1,
            size=file.size,
            url=file.url,
        ))

    vfiles = [
        *sorted(list(vdirs.values()), key=lambda e: e.name),
        *sorted(vfiles, key=lambda e: e.name),
    ]

    if prefix:
        vfiles.insert(0, ProfileFileF(name="..", fake=True))

    return vfiles


@router.get("/profiles/{profile_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_profile_info_page(
        request: Request, profile_id: int, dir_type: ProfileFileLoc | None = None, dir_prefix: str = ".",
):
    profile = await GameProfile.get_or_none(id=profile_id)

    if dir_type not in profile_root_dirs:
        hide_addresses = False
        addresses = await ProfileServerAddress.filter(profile=profile)
        current_root = None
        files = []
    else:
        hide_addresses = True
        addresses = None
        current_root = profile_root_dirs[dir_type]

        dir_prefix = dir_prefix.strip()
        dir_prefix = os.path.relpath(os.path.normpath(os.path.join("/", dir_prefix)), "/")
        if dir_prefix == ".":
            dir_prefix = ""

        files = await _get_profile_files(profile, current_root, dir_prefix)

    unapplied = []
    for file in await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at).order_by("created_at"):
        unapplied.append(UnappliedProfileFile(
            root=file.location.name.lower(),
            path=file.name,
        ))
        if file.action is ProfileFileAction.DOWNLOAD:
            unapplied[-1].created = True
        elif file.action is ProfileFileAction.DELETE:
            unapplied[-1].deleted = True

    return templates.TemplateResponse(request=request, name="profile.jinja2", context={
        "profile": profile,
        "addresses": addresses,
        "hide_addresses": hide_addresses,
        "root_dirs": list(profile_root_dirs.values()),
        "current_root": current_root,
        "files": files,
        "dir_prefix": dir_prefix,
        "unapplied": unapplied,
    })


@router.post("/profiles", response_class=HTMLResponse)
async def admin_create_profile(request: Request, admin: AdminUser, form: ProfileCreateForm = Form()):
    manifest_model = VersionManifest.model_validate_json(await form.manifest.read())
    profile = await GameProfile.create(
        name=form.name,
        description=form.description,
        creator=admin,
        version_manifest=manifest_model.model_dump(),
        public=form.public,
    )

    return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)


@router.post("/profiles/{profile_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_edit_profile(request: Request, profile_id: int, form: ProfileInfoForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)

    profile.name = form.name
    profile.description = form.description
    profile.public = form.public
    await profile.save(update_fields=["name", "description", "public"])

    return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)


@router.post("/profiles/{profile_id}/manifest", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_edit_profile_manifest(request: Request, profile_id: int, form: ProfileManifestForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)
    if form.manifest.size is None or form.manifest.size > 256 * 1024:
        raise HTTPException(400, "Invalid manifest size!")

    manifest_model = VersionManifest.model_validate_json(await form.manifest.read())
    profile.version_manifest = manifest_model.model_dump()
    profile.updated_at = datetime.now(UTC)
    await profile.save(update_fields=["version_manifest", "updated_at"])

    return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)


@router.post("/profiles/{profile_id}/addresses", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_add_profile_address(request: Request, profile_id: int, form: ProfileAddressForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)

    await ProfileServerAddress.create(profile=profile, name=form.name, ip=form.address)

    return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)


@router.post("/profiles/{profile_id}/addresses/{address_id}/delete", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_delete_profile_address(request: Request, profile_id: int, address_id: int):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)

    if (address := await ProfileServerAddress.get_or_none(profile=profile, id=address_id)) is not None:
        await address.delete()

    return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)


@router.post("/profiles/{profile_id}/files", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_upload_profile_files(request: Request, profile_id: int, form: UploadProfileFilesForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)
    if form.dir_type not in profile_root_dirs:
        return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)

    files_to_create = []

    now = datetime.now(timezone.utc)
    for file in form.files:
        if file.size is None or file.size > 128 * 1024 * 1024:
            raise HTTPException(400, "Invalid file size!")

        await file.seek(0)
        sha = sha1()
        while data := await file.read(64 * 1024):
            sha.update(data)
        sha = sha.hexdigest().lower()

        path = f"{form.dir_prefix}/{form.parent}/{file.filename}".replace("\\", "/")
        name = os.path.relpath(os.path.normpath(os.path.join("/", path)), "/")

        await file.seek(0)
        file_id = uuid4().hex
        await S3.upload_object(S3_FILES_BUCKET, f"files/{file_id}/{sha}", file.file)

        files_to_create.append(ProfileFile(
            name=name,
            parent=os.path.dirname(name),
            profile=profile,
            created_at=now,
            location=form.dir_type,
            action=ProfileFileAction.DOWNLOAD,
            sha1=sha,
            size=file.size,
            file_id=file_id,
        ))

    if files_to_create:
        await ProfileFile.bulk_create(files_to_create)

    return RedirectResponse(
        (
            f"{request.url_for('admin_profiles_page', profile_id=profile.id)}"
            f"?dir_type={form.dir_type}&dir_prefix={form.dir_prefix}"
        ),
        303,
    )


@router.post("/profiles/{profile_id}/files/rename", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_rename_profile_files(request: Request, profile_id: int, form: RenameProfileFileForm = Form()):
    result_url = (
        f"{request.url_for('admin_profiles_page', profile_id=profile_id)}"
        f"?dir_type={form.dir_type}&dir_prefix={form.dir_prefix}"
    )

    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)
    if form.dir_type not in profile_root_dirs:
        return RedirectResponse(result_url, 303)

    new_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{form.dir_prefix}/{form.new_name}")), "/")

    files = []
    files_to_create = []
    seen_files = set()

    if form.target_file:
        file = await ProfileFile.get_or_none(profile=profile, location=form.dir_type, id=int(form.target_file))
        search_name = file.name
        if file is not None:
            files = [file]
    elif form.target_dir:
        parent_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{form.dir_prefix}/{form.target_dir}")), "/")
        search_name = parent_name
        files = await ProfileFile.filter(
            profile=profile, location=form.dir_type, parent__startswith=parent_name,
        ).order_by("-created_at")
    else:
        return RedirectResponse(result_url, 303)

    now = datetime.now(UTC)
    for file in files:
        if file.name in seen_files:
            continue
        seen_files.add(file.name)

        file.profile = profile
        if (cloned := file.clone_delete(now)) is not None:
            files_to_create.append(cloned)
        if (cloned := file.clone_rename(new_name + file.name[len(search_name):], now)) is not None:
            files_to_create.append(cloned)

    if files_to_create:
        await ProfileFile.bulk_create(files_to_create)

    return RedirectResponse(result_url, 303)


@router.post("/profiles/{profile_id}/files/delete", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_delete_profile_files(request: Request, profile_id: int, form: DeleteProfileFileForm = Form()):
    result_url = (
        f"{request.url_for('admin_profiles_page', profile_id=profile_id)}"
        f"?dir_type={form.dir_type}&dir_prefix={form.dir_prefix}"
    )

    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)
    if form.dir_type not in profile_root_dirs:
        return RedirectResponse(result_url, 303)

    files = []
    files_to_create = []
    seen_files = set()

    if form.target_file:
        file = await ProfileFile.get_or_none(profile=profile, location=form.dir_type, id=int(form.target_file))
        if file is not None:
            files = [file]
    elif form.target_dir:
        parent_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{form.dir_prefix}/{form.target_dir}")), "/")
        files = await ProfileFile.filter(
            profile=profile, location=form.dir_type, parent__startswith=parent_name
        ).order_by("-created_at")
    else:
        return RedirectResponse(result_url, 303)

    now = datetime.now(UTC)
    for file in files:
        if file.name in seen_files:
            continue
        seen_files.add(file.name)

        file.profile = profile
        if (cloned := file.clone_delete(now)) is not None:
            files_to_create.append(cloned)

    if files_to_create:
        await ProfileFile.bulk_create(files_to_create)

    return RedirectResponse(result_url, 303)


@router.post("/profiles/{profile_id}/apply-files", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def apply_profile_files(request: Request, profile_id: int):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)

    seen_paths = set()
    delete_q = Q()
    for file in await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at).order_by("-created_at"):
        key = (file.location, file.name)
        if key in seen_paths:
            continue
        delete_q |= Q(location=file.location, name=file.name, created_at__lt=file.created_at, id__not=file.id)
        seen_paths.add(key)

    await ProfileFile.filter(delete_q, profile=profile, created_at__gt=profile.updated_at).delete()

    file = await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at).order_by("-created_at").first()
    if file is not None:
        profile.updated_at = datetime.now(timezone.utc)
        await profile.save(update_fields=["updated_at"])

    return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)


@router.post("/profiles/{profile_id}/revert-files", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def revert_profile_files(request: Request, profile_id: int):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(request.url_for("admin_profiles_page"), 303)

    await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at).delete()

    return RedirectResponse(request.url_for("admin_profile_info_page", profile_id=profile.id), 303)


@router.get("/launcher-updates", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_updates_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    updates = await LauncherUpdate.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("-id")
    total = await LauncherUpdate.all().count()

    return templates.TemplateResponse(request=request, name="updates.jinja2", context={
        "updates": updates,
        "available_os": list(UpdateOs),
        "pagination": Pagination(page, PAGE_SIZE, total),
    })


@router.post("/launcher-updates", response_class=HTMLResponse)
async def create_update(request: Request, admin: AdminUser, form: CreateUpdateForm = Form()):
    size = 0
    dir_id = uuid4()
    await form.file.seek(0)

    s3_prefix = f"updates/{dir_id}"

    with ZipFile(form.file.file, "r") as zf:
        await sleep(0)

        with zf.open("Updates.xml", "r") as updates_index:
            updates_index.seek(0, os.SEEK_END)
            size += updates_index.tell()
            if updates_index.tell() > 1024 * 32:
                raise HTTPException(status_code=400, detail="Updates.xml size exceeds 32kb, i aint parsing all of that")

            updates_index.seek(0)
            updates_xml = updates_index.read()

        await sleep(0)

        updates = Updates.from_xml(updates_xml)
        if not updates.checksum or not updates.package_updates or not updates.sha1 or not updates.metadata_name:
            raise HTTPException(status_code=400, detail="Invalid Updates.xml: required `something` is missing")

        await sleep(0)

        with zf.open(updates.metadata_name, "r") as metadata_fp:
            checksum = sha1()
            while data := metadata_fp.read(64 * 1024):
                await sleep(0)
                checksum.update(data)

            if checksum.hexdigest() != updates.sha1:
                raise HTTPException(status_code=400, detail="Root metadata checksum mismatch")

            size += metadata_fp.tell()

            metadata_fp.seek(0)
            await S3.upload_object(S3_FILES_BUCKET, f"{s3_prefix}/{updates.metadata_name}", metadata_fp)

        for update in updates.package_updates:
            with zf.open(f"{update.name}/{update.version}meta.7z", "r") as metadata_fp:
                checksum = sha1()
                while data := metadata_fp.read(64 * 1024):
                    await sleep(0)
                    checksum.update(data)

                if checksum.hexdigest() != update.sha1:
                    raise HTTPException(status_code=400, detail="Update metadata checksum mismatch")

                size += metadata_fp.tell()

                metadata_fp.seek(0)
                await S3.upload_object(
                    S3_FILES_BUCKET, f"{s3_prefix}/{update.name}/{update.version}meta.7z", metadata_fp,
                )

            content_size = 0
            for archive in update.downloadable_archives.split(","):
                with zf.open(f"{update.name}/{update.version}{archive}.sha1", "r") as content_sha_fp:
                    await sleep(0)
                    content_sha = content_sha_fp.read(40).decode("utf8")
                    content_size += 40

                    if len(content_sha) != 40:
                        raise HTTPException(status_code=400, detail=f"Update \"{archive}\" checksum invalid")

                    content_sha_fp.seek(0)
                    await S3.upload_object(
                        S3_FILES_BUCKET, f"{s3_prefix}/{update.name}/{update.version}{archive}.sha1", content_sha_fp,
                    )

                with zf.open(f"{update.name}/{update.version}{archive}", "r") as content_fp:
                    checksum = sha1()
                    while data := content_fp.read(64 * 1024):
                        await sleep(0)
                        content_size += len(data)
                        checksum.update(data)

                    if checksum.hexdigest() != content_sha:
                        raise HTTPException(status_code=400, detail=f"Update \"{archive}\" checksum mismatch")

                    content_fp.seek(0)
                    await S3.upload_object(
                        S3_FILES_BUCKET, f"{s3_prefix}/{update.name}/{update.version}{archive}", content_fp,
                    )

            if content_size != update.update_file.compressed_size:
                raise HTTPException(status_code=400, detail=f"Update size mismatch")

            size += content_size

        with zf.open("Updates.xml", "r") as updates_index:
            await S3.upload_object(S3_FILES_BUCKET, f"{s3_prefix}/Updates.xml", updates_index)

    update = await LauncherUpdate.create(
        created_by=admin,
        code=form.code,
        name=form.name,
        size=size,
        changelog=form.changelog,
        public=False,
        os=form.os,
        dir_id=dir_id,
    )

    return RedirectResponse(request.url_for("admin_update_info_page", update_id=update.id), 303)


@router.post("/launcher-updates-auto", response_class=HTMLResponse)
async def create_update_auto(request: Request, admin: AdminUser, form: CreateUpdateAutoForm = Form()):
    with ZipFile(form.file.file, "r") as zf:
        await sleep(0)

        try:
            with zf.open("ifw_repo_metadata.json", "r") as repo_metadata_file:
                repo_metadata = repo_metadata_file.read()
        except KeyError:
            raise HTTPException(status_code=400, detail="ifw_repo_metadata.xml is not present in archive")

    repo_metadata = json.loads(repo_metadata)
    for field in ("os", "version_code", "version"):
        if field not in repo_metadata:
            raise HTTPException(status_code=400, detail=f"invalid metadata file: \"{field}\" is missing")

    os_value = repo_metadata["os"]
    if os_value not in UpdateOs._value2member_map_:
        raise HTTPException(status_code=400, detail=f"invalid metadata file: \"os\" value is invalid")

    os_type = UpdateOs(os_value)
    code = repo_metadata["version_code"]
    name = repo_metadata["version"]

    return await create_update(request, admin, code, CreateUpdateForm(
        code=code,
        name=name,
        changelog=form.changelog,
        os=os_type,
        file=form.file,
    ))


@router.get("/launcher-updates/{update_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_update_info_page(request: Request, update_id: int):
    if (update := await LauncherUpdate.get_or_none(id=update_id)) is None:
        return RedirectResponse(request.url_for("admin_updates_page"), 303)

    return templates.TemplateResponse(request=request, name="update.jinja2", context={
        "update": update,
    })


@router.post("/launcher-updates/{update_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_edit_launcher_update(request: Request, update_id: int, form: EditUpdateForm = Form()):
    if (update := await LauncherUpdate.get_or_none(id=update_id)) is None:
        return RedirectResponse(request.url_for("admin_updates_page"), 303)

    update.name = form.name
    update.changelog = form.changelog
    update.public = form.public
    await update.save(update_fields=["name", "changelog", "public"])

    return RedirectResponse(request.url_for("admin_update_info_page", update_id=update.id), 303)


@router.get("/launcher-announcements", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_announcements_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    announcements = await LauncherAnnouncement.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("-id")
    total = await LauncherAnnouncement.all().count()

    return templates.TemplateResponse(request=request, name="announcements.jinja2", context={
        "announcements": announcements,
        "available_os": list(AnnouncementOs),
        "pagination": Pagination(page, PAGE_SIZE, total),
    })


@router.post("/launcher-announcements", response_class=HTMLResponse)
async def admin_create_announcement(request: Request, admin: AdminUser, form: CreateAnnouncementForm = Form()):
    if form.active_from >= form.active_to:
        raise HTTPException(status_code=400, detail="\"Active from\" cannot be bigger than \"Active to\"")

    announcement = await LauncherAnnouncement.create(
        created_by=admin,
        name=form.name,
        text=form.text,
        onetime=form.onetime,
        active_from=form.active_from.replace(tzinfo=timezone.utc),
        active_to=form.active_to.replace(tzinfo=timezone.utc),
        os=form.os,
    )

    return RedirectResponse(request.url_for("admin_announcement_info_page", ann_id=announcement.id), 303)



@router.get("/launcher-announcements/{ann_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_announcement_info_page(request: Request, ann_id: int):
    if (ann := await LauncherAnnouncement.get_or_none(id=ann_id)) is None:
        return RedirectResponse(request.url_for("admin_announcements_page"),303)

    return templates.TemplateResponse(request=request, name="announcement.jinja2", context={
        "announcement": ann,
    })


@router.post("/launcher-announcements/{ann_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_edit_launcher_announcement(request: Request, ann_id: int, form: UpdateAnnouncementForm = Form()):
    active_from = form.active_from.replace(tzinfo=timezone.utc)
    active_to = form.active_to.replace(tzinfo=timezone.utc)

    if active_from >= active_to:
        raise HTTPException(status_code=400, detail="\"Active from\" cannot be bigger than \"Active to\"")
    if datetime.now(UTC) >= active_to:
        raise HTTPException(status_code=400, detail="\"Active to\" cannot be in the past")

    if (announcement := await LauncherAnnouncement.get_or_none(id=ann_id)) is None:
        return RedirectResponse(request.url_for("admin_announcements_page"), 303)

    announcement.text = form.text
    announcement.active_from = active_from
    announcement.active_to = active_to
    announcement.onetime = form.onetime
    await announcement.save(update_fields=["text", "active_from", "active_to", "onetime"])

    return RedirectResponse(request.url_for("admin_announcement_info_page", ann_id=announcement.id), 303)


@router.get("/authlib-agent", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_authlib_page(request: Request):
    agent = await AuthlibAgent.filter().order_by("-id").first()
    return templates.TemplateResponse(request=request, name="authlib.jinja2", context={
        "agent": agent,
    })


@router.post("/authlib-agent", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def create_authlib_agent(request: Request, admin: AdminUser, form: UpdateAuthlibForm = Form()):
    if form.file is not None and (form.file.size is None or form.file.size > 1024 * 1024):
        raise HTTPException(status_code=404, detail="Invalid file size")

    if form.file is None or form.file.size == 0:
        prev_agent = await AuthlibAgent.filter().order_by("-id").first()
        if prev_agent is None:
            raise HTTPException(status_code=404, detail="There is no previous authlib agent available")
        file_size = prev_agent.size
        file_sha = prev_agent.sha1
        file_id = prev_agent.file_id
    else:
        form.file.file.seek(0)
        file_size = form.file.size
        file_sha = sha1(form.file.file.read()).hexdigest().lower()
        file_id = uuid4().hex

        await form.file.seek(0)
        await S3.upload_object(S3_FILES_BUCKET, f"authlib-agent/{file_id}/{file_sha}", form.file.file)

    await AuthlibAgent.create(
        created_by=admin,
        size=file_size,
        sha1=file_sha,
        min_launcher_version=form.min_launcher_version,
        file_id=file_id,
    )

    return RedirectResponse(request.url_for("admin_authlib_page"), 303)


@router.get("/capes", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_capes_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    capes = await Cape.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("id")
    total = await Cape.all().count()

    return templates.TemplateResponse(request=request, name="capes.jinja2", context={
        "capes": capes,
        "pagination": Pagination(page, PAGE_SIZE, total),
    })


@router.post("/capes", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_create_cape(request: Request, form: CreateCapeForm = Form()):
    async with in_transaction():
        file_id = uuid4().hex
        new_cape = await Cape.create(
            name=form.name,
            description=form.description,
            public=form.public,
            info_public=form.info_public,
            file_id=file_id,
        )
        await form.file.seek(0)
        await S3.upload_object(S3_GAME_BUCKET, f"capes/{new_cape.id}/{file_id}.png", form.file.file)

    return RedirectResponse(request.url_for("admin_cape_info_page", cape_id=new_cape.id), 303)


@router.get("/capes/{cape_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_cape_info_page(request: Request, cape_id: int):
    if (cape := await Cape.get_or_none(id=cape_id)) is None:
        return RedirectResponse(request.url_for("admin_capes_page"), 303)

    return templates.TemplateResponse(request=request, name="cape.jinja2", context={
        "cape": cape,
    })


@router.post("/capes/{cape_id}", response_class=HTMLResponse, dependencies=[AdminUserDep])
async def admin_edit_cape(request: Request, cape_id: int, form: CapeInfoForm = Form()):
    if (cape := await Cape.get_or_none(id=cape_id)) is None:
        return RedirectResponse(request.url_for("admin_capes_page"), 303)

    cape.name = form.name
    cape.description = form.description
    cape.public = form.public
    cape.info_public = form.info_public
    await cape.save(update_fields=["name", "description", "public", "info_public"])

    return RedirectResponse(request.url_for("admin_cape_info_page", cape_id=cape.id), 303)
