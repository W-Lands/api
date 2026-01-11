import json
import os
from asyncio import sleep
from datetime import datetime, timezone
from functools import partial
from hashlib import sha1
from pathlib import Path
from time import time
from typing import Self, Literal
from uuid import UUID, uuid4
from zipfile import ZipFile

from bcrypt import checkpw, hashpw, gensalt
from fastapi import FastAPI, Depends, Request, HTTPException, Form, UploadFile
from fastui import prebuilt_html, FastUI, AnyComponent, components as c
from fastui.components import forms as f
from fastui.components.display import DisplayLookup
from fastui.events import GoToEvent, AuthEvent, PageEvent
from fastui.forms import fastui_form, FormFile, SelectOption
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel, EmailStr, Field, SecretStr
from pytz import UTC
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.templating import Jinja2Templates
from tortoise.expressions import Q

from wlands.admin.dependencies import admin_opt_auth, NotAuthorized, admin_auth, AdminAuthMaybe, AdminAuthMaybeNew, \
    AdminAuthNew, AdminAuthNewDep, AdminAuthSessionMaybe
from wlands.admin.forms import LoginForm, UserCreateForm, ProfileCreateForm, ProfileInfoForm, ProfileManifestForm, \
    ProfileAddressForm, UploadProfileFilesForm, RenameProfileFileForm, DeleteProfileFileForm, CreateUpdateForm, \
    CreateUpdateAutoForm, UpdateAuthlibForm, EditUpdateForm
from wlands.admin.jinja_filters import format_size, format_enum, format_bool, format_datetime
from wlands.config import S3, S3_FILES_BUCKET
from wlands.launcher.manifest_models import VersionManifest
from wlands.launcher.qtifw_update_xml import Updates
from wlands.models import User, UserSession, UserPydantic, GameSession, ProfilePydantic, GameProfile, ProfileFile, \
    ProfileFileLoc, ProfileFileAction, LauncherUpdate, LauncherUpdatePydantic, UpdateOs, LauncherAnnouncement, \
    LauncherAnnouncementPydantic, AnnouncementOs, AuthlibAgent, AuthlibAgentPydantic, ProfileServerAddress


# TODO: pagination in pages with tables
# TODO: dont use "profile_dir" and "game_dir", use ProfileFileLoc

PREFIX = "/admin"
PREFIX_API = f"{PREFIX}/api"

app = FastAPI()
templates_env = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    autoescape=True,
)
templates = Jinja2Templates(env=templates_env)
templates_env.filters["format_size"] = format_size
templates_env.filters["format_enum"] = format_enum
templates_env.filters["format_bool"] = format_bool
templates_env.filters["format_datetime"] = format_datetime

app_get_fastui = partial(app.get, response_model=FastUI, response_model_exclude_none=True)
app_post_fastui = partial(app.post, response_model=FastUI, response_model_exclude_none=True)


class ProfileRootDir(BaseModel):
    type: str
    name: str
    db_type: ProfileFileLoc


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


profile_root_dirs: dict[str, ProfileRootDir] = {
    "game_dir": ProfileRootDir(
        type="game_dir",
        name="<Game Directory>",
        db_type=ProfileFileLoc.GAME,
    ),
    "profile_dir": ProfileRootDir(
        type="profile_dir",
        name="<Profile Directory>",
        db_type=ProfileFileLoc.PROFILE,
    ),
}


@app.get("/admin-new/login", response_class=HTMLResponse)
def admin_login_page(user: AdminAuthMaybeNew, request: Request):
    if user is not None:
        return RedirectResponse(f"/admin/admin-new/users")

    return templates.TemplateResponse(request=request, name="login.jinja2")


@app.get("/admin-new/logout")
async def admin_logout_page(session: AdminAuthSessionMaybe):
    if session is not None:
        await session.delete()

    resp = RedirectResponse(f"/admin/admin-new/login", 303)
    resp.delete_cookie("auth_token")
    return resp


@app.post("/admin-new/login", response_class=HTMLResponse)
async def admin_login(user: AdminAuthMaybeNew, request: Request, form: LoginForm = Form()):
    if user is not None:
        return RedirectResponse(f"/admin/admin-new/users")

    error_resp = templates.TemplateResponse(request=request, name="login.jinja2", context={
        "error": "Wrong credentials."
    })

    if (user := await User.get_or_none(email=form.email, admin=True, banned=False)) is None:
        return error_resp
    if not checkpw(form.password.get_secret_value().encode(), user.password.encode()):
        return error_resp

    session = await UserSession.create(user=user)

    resp = RedirectResponse(f"/admin/admin-new/users", 303)
    resp.set_cookie(
        "auth_token", f"{user.id.hex}{session.id.hex}{session.token}", expires=int(session.expires_at.timestamp())
    )
    return resp


async def _users_page(request: Request, page: int, create_error: str | None = None, create_nickname: str = ""):
    PAGE_SIZE = 25

    users = await User.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("created_at")
    return templates.TemplateResponse(request=request, name="users.jinja2", context={
        "users": users,
        "error": create_error,
        "show_create_modal": bool(create_error),
        "create_form_nickname": create_nickname,
    })


@app.get("/admin-new/users", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_users_page(request: Request, page: int = 1):
    return await _users_page(request, page)


@app.post("/admin-new/users", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_create_user(request: Request, form: UserCreateForm = Form()):
    if await User.filter(nickname=form.nickname).exists():
        return await _users_page(request, 1, "User with this nickname already exists.", form.nickname)

    new_user = await User.create(
        email=f"{form.nickname}@wlands.pepega",
        nickname=form.nickname,
        password=hashpw(form.password.get_secret_value().encode("utf8"), gensalt()).decode("utf8"),
    )

    return RedirectResponse(f"/admin/admin-new/users/{new_user.id}", 303)


@app.get("/admin-new/users/{user_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_user_info_page(request: Request, user_id: UUID):
    target = await User.get_or_none(id=user_id)
    return templates.TemplateResponse(request=request, name="user.jinja2", context={
        "user": target,
    })


@app.post("/admin-new/users/{user_id}/toggle-ban", response_class=HTMLResponse)
async def admin_ban_unban_user(request: Request, user_id: UUID, admin: AdminAuthNew):
    if (target := await User.get_or_none(id=user_id)) is None:
        return RedirectResponse(f"/admin/admin-new/users", 303)
    if target.id == admin.id or target.admin:
        return templates.TemplateResponse(request=request, name="user.jinja2", context={
            "user": target,
            "ban_error": "You can't ban this user",
        })

    target.banned = not target.banned
    if target.banned:
        await GameSession.filter(user=target).delete()
        await UserSession.filter(user=target).delete()

    await target.save(update_fields=["banned"])

    return RedirectResponse(f"/admin/admin-new/users/{target.id}", 303)


@app.post("/admin-new/users/{user_id}", response_class=HTMLResponse)
async def admin_edit_user(request: Request, user_id: UUID, admin: AdminAuthNew, nickname: str = Form()):
    if (target := await User.get_or_none(id=user_id)) is None:
        return RedirectResponse(f"/admin/admin-new/users", 303)
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

    return RedirectResponse(f"/admin/admin-new/users/{target.id}", 303)


@app.get("/admin-new/profiles", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_profiles_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    profiles = await GameProfile.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("id")
    return templates.TemplateResponse(request=request, name="profiles.jinja2", context={
        "profiles": profiles,
    })


async def _get_profile_files(profile: GameProfile, root: ProfileRootDir, prefix: str) -> list[ProfileFileF]:
    files = await ProfileFile.filter(
        profile=profile, location=root.db_type, parent__startswith=prefix,
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


@app.get("/admin-new/profiles/{profile_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_profile_info_page(
        request: Request, profile_id: int, dir_type: str | None = None, dir_prefix: str = ".",
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


@app.post("/admin-new/profiles", response_class=HTMLResponse)
async def admin_create_profile(admin: AdminAuthNew, form: ProfileCreateForm = Form()):
    manifest_model = VersionManifest.model_validate_json(await form.manifest.read())
    profile = await GameProfile.create(
        name=form.name,
        description=form.description,
        creator=admin,
        version_manifest=manifest_model.model_dump(),
        public=form.public,
    )

    return RedirectResponse(f"/admin/admin-new/profiles/{profile.id}", 303)


@app.post("/admin-new/profiles/{profile_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_edit_profile(profile_id: int, form: ProfileInfoForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)

    profile.name = form.name
    profile.description = form.description
    profile.public = form.public
    await profile.save(update_fields=["name", "description", "public"])

    return RedirectResponse(f"/admin/admin-new/profiles/{profile.id}", 303)


@app.post("/admin-new/profiles/{profile_id}/manifest", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_edit_profile_manifest(profile_id: int, form: ProfileManifestForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)
    if form.manifest.size is None or form.manifest.size > 256 * 1024:
        raise HTTPException(400, "Invalid manifest size!")

    manifest_model = VersionManifest.model_validate_json(await form.manifest.read())
    profile.version_manifest = manifest_model.model_dump()
    profile.updated_at = datetime.now(UTC)
    await profile.save(update_fields=["version_manifest", "updated_at"])

    return RedirectResponse(f"/admin/admin-new/profiles/{profile.id}", 303)


@app.post("/admin-new/profiles/{profile_id}/addresses", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_add_profile_address(profile_id: int, form: ProfileAddressForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)

    await ProfileServerAddress.create(profile=profile, name=form.name, ip=form.address)

    return RedirectResponse(f"/admin/admin-new/profiles/{profile.id}", 303)


@app.post("/admin-new/profiles/{profile_id}/addresses/{address_id}/delete", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_delete_profile_address(profile_id: int, address_id: int):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)

    if (address := await ProfileServerAddress.get_or_none(profile=profile, id=address_id)) is not None:
        await address.delete()

    return RedirectResponse(f"/admin/admin-new/profiles/{profile.id}", 303)


@app.post("/admin-new/profiles/{profile_id}/files", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_upload_profile_files(profile_id: int, form: UploadProfileFilesForm = Form()):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)
    if form.dir_type not in profile_root_dirs:
        return RedirectResponse(f"/admin/admin-new/profiles/{profile_id}", 303)

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
            location=profile_root_dirs[form.dir_type].db_type,
            action=ProfileFileAction.DOWNLOAD,
            sha1=sha,
            size=file.size,
            file_id=file_id,
        ))

    if files_to_create:
        await ProfileFile.bulk_create(files_to_create)

    return RedirectResponse(
        f"/admin/admin-new/profiles/{profile_id}?dir_type={form.dir_type}&dir_prefix={form.dir_prefix}", 303,
    )


@app.post("/admin-new/profiles/{profile_id}/files/rename", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_rename_profile_files(profile_id: int, form: RenameProfileFileForm = Form()):
    result_url = f"/admin/admin-new/profiles/{profile_id}?dir_type={form.dir_type}&dir_prefix={form.dir_prefix}"

    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)
    if form.dir_type not in profile_root_dirs:
        return RedirectResponse(result_url, 303)

    location = profile_root_dirs[form.dir_type].db_type
    new_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{form.dir_prefix}/{form.new_name}")), "/")

    files = []
    files_to_create = []
    seen_files = set()

    if form.target_file:
        file = await ProfileFile.get_or_none(profile=profile, location=location, id=int(form.target_file))
        search_name = file.name
        if file is not None:
            files = [file]
    elif form.target_dir:
        parent_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{form.dir_prefix}/{form.target_dir}")), "/")
        search_name = parent_name
        files = await ProfileFile.filter(
            profile=profile, location=location, parent__startswith=parent_name,
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


@app.post("/admin-new/profiles/{profile_id}/files/delete", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_delete_profile_files(profile_id: int, form: DeleteProfileFileForm = Form()):
    result_url = f"/admin/admin-new/profiles/{profile_id}?dir_type={form.dir_type}&dir_prefix={form.dir_prefix}"

    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)
    if form.dir_type not in profile_root_dirs:
        return RedirectResponse(result_url, 303)

    location = profile_root_dirs[form.dir_type].db_type

    files = []
    files_to_create = []
    seen_files = set()

    if form.target_file:
        file = await ProfileFile.get_or_none(profile=profile, location=location, id=int(form.target_file))
        if file is not None:
            files = [file]
    elif form.target_dir:
        parent_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{form.dir_prefix}/{form.target_dir}")), "/")
        files = await ProfileFile.filter(
            profile=profile, location=location, parent__startswith=parent_name
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


@app.post("/admin-new/profiles/{profile_id}/apply-files", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def apply_profile_files(profile_id: int):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)

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

    return RedirectResponse(f"/admin/admin-new/profiles/{profile.id}", 303)


@app.post("/admin-new/profiles/{profile_id}/revert-files", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def revert_profile_files(profile_id: int):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        return RedirectResponse(f"/admin/admin-new/profiles", 303)

    await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at).delete()

    return RedirectResponse(f"/admin/admin-new/profiles/{profile.id}", 303)


@app.get("/admin-new/launcher-updates", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_updates_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    updates = await LauncherUpdate.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("-id")
    return templates.TemplateResponse(request=request, name="updates.jinja2", context={
        "updates": updates,
    })


@app.post("/admin-new/launcher-updates", response_class=HTMLResponse)
async def create_update(admin: AdminAuthNew, form: CreateUpdateForm = Form()):
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

    return RedirectResponse(f"/admin/admin-new/launcher-updates/{update.id}", 303)


@app.post("/admin-new/launcher-updates-auto", response_class=HTMLResponse)
async def create_update_auto(admin: AdminAuthNew, form: CreateUpdateAutoForm = Form()):
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

    return await create_update(admin, code, name, form.changelog, os_type, form.file)


@app.get("/admin-new/launcher-updates/{update_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_update_info_page(request: Request, update_id: int):
    if (update := await LauncherUpdate.get_or_none(id=update_id)) is None:
        return RedirectResponse(f"/admin/admin-new/launcher-updates", 303)

    return templates.TemplateResponse(request=request, name="update.jinja2", context={
        "update": update,
    })


@app.post("/admin-new/launcher-updates/{update_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_edit_launcher_update(update_id: int, form: EditUpdateForm = Form()):
    if (update := await LauncherUpdate.get_or_none(id=update_id)) is None:
        return RedirectResponse(f"/admin/admin-new/launcher-updates", 303)

    update.name = form.name
    update.changelog = form.changelog
    update.public = form.public
    await update.save(update_fields=["name", "changelog", "public"])

    return RedirectResponse(f"/admin/admin-new/launcher-updates/{update.id}", 303)


@app.get("/admin-new/launcher-announcements", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_announcements_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    announcements = await LauncherAnnouncement.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("-id")
    return templates.TemplateResponse(request=request, name="announcements.jinja2", context={
        "announcements": announcements,
    })


@app.get("/admin-new/launcher-announcements/{ann_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_update_info_page(request: Request, ann_id: int):
    ann = await LauncherAnnouncement.get_or_none(id=ann_id)

    return templates.TemplateResponse(request=request, name="announcement.jinja2", context={
        "announcement": ann,
    })


@app.get("/admin-new/authlib-agent", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_authlib_page(request: Request):
    agent = await AuthlibAgent.filter().order_by("-id").first()
    return templates.TemplateResponse(request=request, name="authlib.jinja2", context={
        "agent": agent,
    })


@app.post("/admin-new/authlib-agent", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def create_authlib_agent(admin: AdminAuthNew, form: UpdateAuthlibForm = Form()):
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

    return RedirectResponse(f"/admin/admin-new/authlib-agent", 303)


@app_post_fastui("/api/admin/launcher-announcements/")
@app_post_fastui("/api/admin/launcher-announcements")
async def create_announcement(
        admin: User = Depends(admin_auth),
        name: str = Form(), text: str = Form(), os_type: AnnouncementOs = Form(), onetime: bool = Form(default=False),
        active_from: datetime = Form(), active_to: datetime = Form(),
):
    if active_from >= active_to:
        raise HTTPException(status_code=400, detail="\"Active from\" cannot be bigger than \"Active to\"")

    announcement = await LauncherAnnouncement.create(
        created_by=admin,
        name=name,
        text=text,
        onetime=onetime,
        active_from=active_from.replace(tzinfo=timezone.utc),
        active_to=active_to.replace(tzinfo=timezone.utc),
        os=os_type,
    )

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/launcher-announcements/{announcement.id}?{time()}"))]


@app_post_fastui("/api/admin/launcher-announcements/{announcement_id}/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/launcher-announcements/{announcement_id}", dependencies=[Depends(admin_auth)])
async def edit_launcher_announcement(
        announcement_id: int,
        text: str = Form(), onetime: bool = Form(default=False),
        active_from: datetime = Form(), active_to: datetime = Form(),
):
    if active_from >= active_to:
        raise HTTPException(status_code=400, detail="\"Active from\" cannot be bigger than \"Active to\"")

    if (announcement := await LauncherAnnouncement.get_or_none(id=announcement_id)) is None:
        raise HTTPException(status_code=404, detail="Announcement not found")

    announcement.text = text
    announcement.active_from = active_from.replace(tzinfo=timezone.utc)
    announcement.active_to = active_to.replace(tzinfo=timezone.utc)
    announcement.onetime = onetime
    await announcement.save(update_fields=["text", "active_from", "active_to", "onetime"])

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/launcher-announcements/{announcement.id}?{time()}"))]


@app.get("/{path:path}")
async def html_landing() -> HTMLResponse:
    return HTMLResponse(prebuilt_html(title="WLands admin panel", api_root_url=PREFIX_API))


@app.exception_handler(NotAuthorized)
async def not_authorized_handler(request: Request, exc: NotAuthorized):
    resp = RedirectResponse(f"/admin/admin-new/login")
    resp.delete_cookie("auth_token")
    return resp
