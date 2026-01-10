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
from wlands.admin.forms import LoginForm
from wlands.admin.jinja_filters import format_size, format_enum, format_bool, format_datetime
from wlands.config import S3, S3_FILES_BUCKET
from wlands.launcher.manifest_models import VersionManifest
from wlands.launcher.qtifw_update_xml import Updates
from wlands.models import User, UserSession, UserPydantic, GameSession, ProfilePydantic, GameProfile, ProfileFile, \
    ProfileFileLoc, ProfileFileAction, LauncherUpdate, LauncherUpdatePydantic, UpdateOs, LauncherAnnouncement, \
    LauncherAnnouncementPydantic, AnnouncementOs, AuthlibAgent, AuthlibAgentPydantic, ProfileServerAddress

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


@app.get("/admin-new/users", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_users_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    users = await User.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("created_at")
    return templates.TemplateResponse(request=request, name="users.jinja2", context={
        "users": users,
    })


@app.get("/admin-new/users/{user_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_user_info_page(request: Request, user_id: UUID):
    target = await User.get_or_none(id=user_id)
    return templates.TemplateResponse(request=request, name="user.jinja2", context={
        "user": target,
    })


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

        paths = file_path.split("/")
        if len(paths) > 1:
            vdir = vdirs.get(paths[0])
            if vdir is None:
                name = f"{paths[0]}/"
                vdirs[paths[0]] = vdir = ProfileFileF(name=name, size=0)

            vdir.size += file.size
            continue

        vfiles.append(ProfileFileF(
            name=file.name,
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


    return templates.TemplateResponse(request=request, name="profile.jinja2", context={
        "profile": profile,
        "addresses": addresses,
        "hide_addresses": hide_addresses,
        "root_dirs": list(profile_root_dirs.values()),
        "current_root": current_root,
        "files": files,
        "dir_prefix": dir_prefix,
    })


@app.get("/admin-new/launcher-updates", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_updates_page(request: Request, page: int = 1):
    PAGE_SIZE = 25

    updates = await LauncherUpdate.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("-id")
    return templates.TemplateResponse(request=request, name="updates.jinja2", context={
        "updates": updates,
    })


@app.get("/admin-new/launcher-updates/{update_id}", response_class=HTMLResponse, dependencies=[AdminAuthNewDep])
async def admin_update_info_page(request: Request, update_id: int):
    update = await LauncherUpdate.get_or_none(id=update_id)

    return templates.TemplateResponse(request=request, name="update.jinja2", context={
        "update": update,
    })


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


class ActionMode(c.Div):
    ...


def make_page(title: str, action_mode: ActionMode | AnyComponent | None = None, *components: AnyComponent) -> list[AnyComponent]:
    if not isinstance(action_mode, ActionMode):
        if action_mode is not None:
            components = [action_mode, *components]

    return [
        c.PageTitle(text=f"W-Lands - {title}"),
        c.Navbar(
            title="W-Lands",
            title_event=GoToEvent(url=f"{PREFIX}/users"),
            start_links=[
                c.Link(
                    components=[c.Text(text="Users")],
                    on_click=GoToEvent(url=f"{PREFIX}/users"),
                    active=f'startswith:{PREFIX}/users',
                ),
                c.Link(
                    components=[c.Text(text="Profiles")],
                    on_click=GoToEvent(url=f"{PREFIX}/profiles"),
                    active=f'startswith:{PREFIX}/profiles',
                ),
                c.Link(
                    components=[c.Text(text="Launcher Updates")],
                    on_click=GoToEvent(url=f"{PREFIX}/launcher-updates"),
                    active=f'startswith:{PREFIX}/launcher-updates',
                ),
                c.Link(
                    components=[c.Text(text="Launcher Announcements")],
                    on_click=GoToEvent(url=f"{PREFIX}/launcher-announcements"),
                    active=f'startswith:{PREFIX}/launcher-announcements',
                ),
                c.Link(
                    components=[c.Text(text="Authlib agent")],
                    on_click=GoToEvent(url=f"{PREFIX}/authlib-agent"),
                    active=f'startswith:{PREFIX}/authlib-agent',
                ),
            ],
            end_links=[
                c.Link(
                    components=[c.Text(text="Logout")],
                    on_click=AuthEvent(token=False, url=f"{PREFIX}/login")
                ),
            ],
        ),
        c.Page(
            components=[
                *([action_mode] if isinstance(action_mode, ActionMode) else ()),
                c.Heading(text=title),
                *components,
            ],
        ),
    ]


@app_post_fastui("/api/admin/users/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/users", dependencies=[Depends(admin_auth)])
async def create_user(nickname: str = Form(), password: str = Form()):
    user = await User.create(
        email=f"{nickname}@wlands.pepega",
        nickname=nickname,
        password=hashpw(password.encode("utf8"), gensalt()).decode("utf8"),
    )

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/users/{user.id}?{time()}"))]


@app_post_fastui("/api/admin/users/{user_id}/{action}/")
@app_post_fastui("/api/admin/users/{user_id}/{action}")
async def ban_unban_user(user_id: UUID, action: str, admin: User = Depends(admin_auth)):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="You can not ban this user")
    if (user := await User.get_or_none(id=user_id)) is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user == admin or user.admin:
        raise HTTPException(status_code=400, detail="You can not ban this user")

    if action.lower() == "ban":
        await GameSession.filter(user=user).delete()
        await UserSession.filter(user=user).delete()
        user.banned = True
    else:
        user.banned = False

    await user.save(update_fields=["banned"])

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/users/{user_id}?{time()}"))]


@app_post_fastui("/api/admin/users/{user_id}/")
@app_post_fastui("/api/admin/users/{user_id}")
async def edit_user(user_id: UUID, nickname: str = Form(), admin: User = Depends(admin_auth)):
    if user_id == admin.id:
        raise HTTPException(status_code=400, detail="You can not edit this user")
    if (user := await User.get_or_none(id=user_id)) is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user == admin or user.admin:
        raise HTTPException(status_code=400, detail="You can not edit this user")

    user.nickname = nickname
    user.email = f"{nickname}@wlands.pepega"
    await user.save(update_fields=["nickname", "email"])

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/users/{user_id}?{time()}"))]


@app_post_fastui("/api/admin/profiles/")
@app_post_fastui("/api/admin/profiles")
async def create_profile(
        admin: User = Depends(admin_auth),
        name: str = Form(), description: str = Form(), public: bool = Form(default=False),
        manifest: UploadFile = FormFile(accept="application/json,.json", max_size=256 * 1024),
):
    manifest_model = VersionManifest.model_validate_json(await manifest.read())
    profile = await GameProfile.create(
        name=name,
        description=description,
        creator=admin,
        version_manifest=manifest_model.model_dump(),
        public=public,
    )

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/profiles/{profile.id}?{time()}"))]


@app_post_fastui("/api/admin/profiles/{profile_id}/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}", dependencies=[Depends(admin_auth)])
async def edit_profile(
        profile_id: int,
        name: str = Form(), description: str = Form(), public: bool = Form(default=False),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    profile.name = name
    profile.description = description
    profile.public = public
    await profile.save(update_fields=["name", "description", "public"])

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/profiles/{profile.id}?{time()}"))]


@app_post_fastui("/api/admin/profiles/{profile_id}/manifest/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/manifest", dependencies=[Depends(admin_auth)])
async def edit_profile_manifest(
        profile_id: int,
        manifest: UploadFile = FormFile(accept="application/json,.json", max_size=256 * 1024),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    manifest_model = VersionManifest.model_validate_json(await manifest.read())
    profile.version_manifest = manifest_model.model_dump()
    profile.updated_at = datetime.now(UTC)
    await profile.save(update_fields=["version_manifest", "updated_at"])

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/profiles/{profile.id}?{time()}"))]


@app_post_fastui("/api/admin/profiles/{profile_id}/files/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/files", dependencies=[Depends(admin_auth)])
async def upload_profile_files(
        profile_id: int,
        directory: str | None = Form(default=None), file_loc: ProfileFileLoc = Form(), dir_type: str | None = Form(),
        dir_prefix: str = Form(default=""),
        files: list[UploadFile] = FormFile(max_size=128 * 1024 * 1024),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    files_to_create = []

    now = datetime.now(timezone.utc)
    for file in files:
        file.file.seek(0)
        sha = sha1()
        sha.update(file.file.read())
        sha = sha.hexdigest().lower()

        path = f"{dir_prefix}/{directory}/{file.filename}".replace("\\", "/")
        name = os.path.relpath(os.path.normpath(os.path.join("/", path)), "/")

        file.file.seek(0)
        file_id = uuid4().hex
        await S3.upload_object(S3_FILES_BUCKET, f"files/{file_id}/{sha}", file.file)

        files_to_create.append(ProfileFile(
            name=name,
            parent=os.path.dirname(name),
            profile=profile,
            created_at=now,
            location=file_loc,
            action=ProfileFileAction.DOWNLOAD,
            sha1=sha,
            size=file.size,
            file_id=file_id,
        ))

    if files_to_create:
        await ProfileFile.bulk_create(files_to_create)

    return [
        c.FireEvent(
            event=GoToEvent(
                url=f"{PREFIX}/profiles/{profile.id}?{time()}&dir_type={dir_type}&dir_prefix={dir_prefix}",
            )
        )
    ]


@app_post_fastui("/api/admin/profiles/{profile_id}/files/rename/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/files/rename", dependencies=[Depends(admin_auth)])
async def rename_profile_files(
        profile_id: int, name: str = Form(),
        file_loc: ProfileFileLoc = Form(), target_type: Literal["file", "dir"] = Form(), target: str = Form(),
        dir_type: str = Form(default=""), dir_prefix: str = Form(default=""),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    new_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{dir_prefix}/{name}")), "/")
    search_name = ".."

    files = []
    files_to_create = []
    seen_files = set()

    if target_type == "file":
        file = await ProfileFile.get_or_none(
            profile=profile, location=file_loc, id=int(target),
        )
        search_name = file.name
        if file is not None:
            files.append(file)
    elif target_type == "dir":
        parent_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{dir_prefix}/{target}")), "/")
        search_name = parent_name
        files = await ProfileFile.filter(
            profile=profile, location=file_loc, parent__startswith=parent_name
        ).order_by("-created_at")

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

    return [
        c.FireEvent(
            event=GoToEvent(
                url=f"{PREFIX}/profiles/{profile.id}?{time()}&dir_type={dir_type}&dir_prefix={dir_prefix}",
            )
        )
    ]


@app_post_fastui("/api/admin/profiles/{profile_id}/files/delete/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/files/delete", dependencies=[Depends(admin_auth)])
async def delete_profile_files(
        profile_id: int,
        file_loc: ProfileFileLoc = Form(), target_type: Literal["file", "dir"] = Form(), target: str = Form(),
        dir_type: str = Form(default=""), dir_prefix: str = Form(default=""),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    files = []
    files_to_create = []
    seen_files = set()

    if target_type == "file":
        file = await ProfileFile.get_or_none(profile=profile, location=file_loc, id=int(target))
        if file is not None:
            files.append(file)
    elif target_type == "dir":
        parent_name = os.path.relpath(os.path.normpath(os.path.join("/", f"{dir_prefix}/{target}")), "/")
        files = await ProfileFile.filter(profile=profile, location=file_loc, parent__startswith=parent_name)\
            .order_by("-created_at")

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

    return [
        c.FireEvent(
            event=GoToEvent(
                url=f"{PREFIX}/profiles/{profile.id}?{time()}&dir_type={dir_type}&dir_prefix={dir_prefix}",
            )
        )
    ]


@app_get_fastui("/api/admin/profiles/{profile_id}/unapplied-files/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/profiles/{profile_id}/unapplied-files", dependencies=[Depends(admin_auth)])
async def unapplied_files_list(profile_id: int):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    dir_name = {
        ProfileFileLoc.GAME: "<game>",
        ProfileFileLoc.PROFILE: "<profile>",
    }

    result = []
    files = await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at)\
        .order_by("created_at")

    for file in files:
        text = f" - **{dir_name.get(file.location, 'Unknown')}**/`{file.name}`"
        if file.action is ProfileFileAction.DOWNLOAD:
            text += " - new"
        elif file.action is ProfileFileAction.DELETE:
            text += " - deleted (or renamed)"
        else:
            text += " - **UNKNOWN ACTION**"

        result.append(text)

    return [
        c.Markdown(text="\n".join(result))
    ]


@app_post_fastui("/api/admin/profiles/{profile_id}/apply-files/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/apply-files", dependencies=[Depends(admin_auth)])
async def apply_profile_files(
        profile_id: int,
        dir_type: str = Form(default=""), dir_prefix: str = Form(default=""),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

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

    return [
        c.FireEvent(
            event=GoToEvent(
                url=f"{PREFIX}/profiles/{profile.id}?{time()}&dir_type={dir_type}&dir_prefix={dir_prefix}",
            )
        )
    ]


@app_post_fastui("/api/admin/profiles/{profile_id}/revert-files/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/revert-files", dependencies=[Depends(admin_auth)])
async def revert_profile_files(
        profile_id: int,
        dir_type: str = Form(default=""), dir_prefix: str = Form(default=""),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at).delete()

    return [
        c.FireEvent(
            event=GoToEvent(
                url=f"{PREFIX}/profiles/{profile.id}?{time()}&dir_type={dir_type}&dir_prefix={dir_prefix}",
            )
        )
    ]


class ProfileFileV(BaseModel):
    id: int
    created_at_fmt: str
    name: str
    file_id: str
    sha1: str
    size: int

    url: str
    size_fmt: str

    action_rename_url: str
    action_delete_url: str

    action_rename: str = "Rename"
    action_delete: str = "Delete"

    @classmethod
    def from_db(
            cls, file: ProfileFile | None, name: str, dir_type: str, dir_prefix: str,
            profile_id: int | None = None,
    ) -> Self:
        if file is not None and profile_id is None:
            profile_id = file.profile_id
        profile_prefix = f"{PREFIX}/profiles/{profile_id}/"
        ctx_prefix = f"?dir_type={dir_type}&dir_prefix={dir_prefix}"

        if file is None:
            action_prefix = f"{profile_prefix}{ctx_prefix}&target_type=dir&target={name}"
            action_rename = "Rename" if name != ".." else ""
            action_delete = "Delete" if name != ".." else ""
            action_rename_url = f"{action_prefix}&mode=rename" if name != ".." else ""
            action_delete_url = f"{action_prefix}&mode=delete" if name != ".." else ""

            return cls(
                id=-1,
                created_at_fmt="",
                name=name,
                file_id="",
                sha1="",
                size=0,
                url=f"{profile_prefix}?dir_type={dir_type}&dir_prefix={dir_prefix}/{name}",
                size_fmt="",
                action_rename=action_rename,
                action_delete=action_delete,
                action_rename_url=action_rename_url,
                action_delete_url=action_delete_url,
            )

        action_prefix = f"{profile_prefix}{ctx_prefix}&target_type=file&target={file.id}"
        return cls(
            id=file.id,
            created_at_fmt=file.created_at.strftime("%d.%m.%Y %H:%M:%S"),
            name=name,
            file_id=file.file_id,
            sha1=file.sha1,
            size=file.size,
            url=file.url,
            size_fmt=format_size(file.size),
            action_rename_url=f"{action_prefix}&mode=rename",
            action_delete_url=f"{action_prefix}&mode=delete",
        )


def HiddenInput(*, name: str, value: str | int, required: bool = True) -> c.FormFieldInput:
    return c.FormFieldInput(
        name=name,
        initial=str(value),
        html_type="hidden",
        required=required,
        class_name="d-none",
        title="",
    )


@app_post_fastui("/api/admin/profiles/{profile_id}/addresses/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/addresses", dependencies=[Depends(admin_auth)])
async def add_profile_address(
        profile_id: int,
        name: str = Form(), address: str = Form(),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    await ProfileServerAddress.create(profile=profile, name=name, ip=address)

    return [
        c.FireEvent(event=GoToEvent(url=f"{PREFIX}/profiles/{profile.id}?{time()}"))
    ]


@app_post_fastui("/api/admin/profiles/{profile_id}/addresses/{address_id}/delete/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/addresses/{address_id}/delete", dependencies=[Depends(admin_auth)])
async def delete_profile_address(
        profile_id: int, address_id: int,
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    if (address := await ProfileServerAddress.get_or_none(id=address_id)) is None:
        raise HTTPException(status_code=404, detail="Address not found")

    await address.delete()

    return [
        c.FireEvent(event=GoToEvent(url=f"{PREFIX}/profiles/{profile.id}?{time()}"))
    ]


def ips_table_head() -> c.Div:
    return c.Div(
        class_name="row border-bottom pb-2 fw-bold",
        components=[
            c.Div(
                class_name="col",
                components=[
                    c.Div(components=[c.Text(text="Name")]),
                ],
            ),
            c.Div(
                class_name="col",
                components=[
                    c.Div(components=[c.Text(text="Ip")]),
                ],
            ),
            c.Div(
                class_name="col d-flex flex-row-reverse",
                components=[
                    c.Div(components=[c.Text(text="Action")]),
                ],
            ),
        ]
    )


def ips_table_row(profile_id: int, address_id: int, name: str, ip: str) -> c.Div:
    address_prefix_api = f"{PREFIX_API}/admin/profiles/{profile_id}/addresses/{address_id}"
    delete_event_name = f"delete-address-{address_id}-form-submit"

    return c.Div(
        class_name="row border-bottom my-1 py-2",
        components=[
            c.Form(
                form_fields=[
                    HiddenInput(
                        name="profile_id",
                        value=profile_id,
                        required=True,
                    ),
                    HiddenInput(
                        name="address_id",
                        value=address_id,
                        required=True,
                    ),
                ],
                submit_url=f"{address_prefix_api}/delete",
                submit_trigger=PageEvent(name=delete_event_name),
                footer=[],
            ),

            c.Div(
                class_name="col d-flex align-items-center",
                components=[
                    c.Div(components=[c.Text(text=name)]),
                ],
            ),
            c.Div(
                class_name="col d-flex align-items-center",
                components=[
                    c.Div(components=[c.Text(text=ip)]),
                ],
            ),
            c.Div(
                class_name="col d-flex flex-row-reverse align-items-center",
                components=[
                    c.Button(text="Remove", class_name="+ btn-danger", on_click=PageEvent(name=delete_event_name)),
                ],
            ),
        ]
    )


@app_get_fastui("/api/admin/profiles/{profile_id}/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/profiles/{profile_id}", dependencies=[Depends(admin_auth)])
async def profile_info(
        profile_id: int, dir_type: str | None = None, dir_prefix: str = "",
        mode: Literal["rename", "delete"] | None = None, target_type: Literal["file", "dir"] | None = None,
        target: str | None = None,
) -> list[AnyComponent]:
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="User not found")

    profile_prefix = f"{PREFIX}/profiles/{profile.id}/"
    profile_prefix_api = f"{PREFIX_API}/admin/profiles/{profile.id}"

    file_loc: ProfileFileLoc | None = None

    dir_prefix = dir_prefix.strip()
    dir_prefix = os.path.relpath(os.path.normpath(os.path.join("/", dir_prefix)), "/")
    if dir_prefix == ".":
        dir_prefix = ""

    target_obj = None

    if dir_type in profile_dirs:
        prof_dir = profile_dirs[dir_type]
        file_loc = prof_dir.db_type

        files = await ProfileFile.filter(
            profile=profile, location=file_loc, parent__startswith=dir_prefix,
        ).order_by("-created_at")

        vdirs = {}
        vfiles = []
        seen_files = set()

        for file in files:
            file_path = file.name[len(dir_prefix):].lstrip("/")
            if file_path in seen_files:
                continue

            seen_files.add(file_path)
            if file.action is ProfileFileAction.DELETE:
                continue

            paths = file_path.split("/")
            if len(paths) > 1:
                vdir = vdirs.get(paths[0])
                if vdir is None:
                    name = f"{paths[0]}/"
                    vdirs[paths[0]] = vdir = ProfileFileV.from_db(None, name, dir_type, dir_prefix, profile.id)
                    if target_type == "dir" and target == name:
                        target_obj = vdir

                vdir.size += file.size
                vdir.size_fmt = format_size(vdir.size)

                continue

            vfiles.append(ProfileFileV.from_db(file, file_path, dir_type, dir_prefix))
            if target_type == "file" and target == str(file.id):
                target_obj = vfiles[-1]

        vfiles = [
            *sorted(list(vdirs.values()), key=lambda e: e.name),
            *sorted(vfiles, key=lambda e: e.name),
        ]

        if dir_prefix:
            vfiles.insert(0, ProfileFileV.from_db(None, "..", dir_type, dir_prefix, profile.id))

        files_table = [
            c.Heading(text=prof_dir.name, level=3, class_name="+ mt-3"),
            c.Div(
                class_name="+ vstack",
                components=[
                    c.Link(
                        components=[c.Text(text=".. Back")],
                        on_click=GoToEvent(url=profile_prefix),
                    ),
                    c.Link(
                        components=[c.Text(text="Upload file")],
                        on_click=PageEvent(name="file-upload-modal"),
                    ),
                ],
            ),
            c.Table(
                data=vfiles,
                data_model=ProfileFileV,
                columns=[
                    DisplayLookup(field="name", on_click=GoToEvent(url="{url}")),
                    DisplayLookup(field="created_at_fmt", title="Modified At"),
                    DisplayLookup(field="sha1"),
                    DisplayLookup(field="size_fmt", title="Size"),
                    DisplayLookup(field="action_rename", title="Actions", on_click=GoToEvent(url="{action_rename_url}")),
                    DisplayLookup(field="action_delete", title="", on_click=GoToEvent(url="{action_delete_url}")),
                ],
                class_name="+ mt-2",
            )
        ]
    else:
        files_table = [
            c.Table(
                data=list(profile_dirs.values()),
                columns=[
                    DisplayLookup(
                        title="Directory",
                        field="name",
                        on_click=GoToEvent(url=f"{profile_prefix}?dir_type={{type}}")
                    ),
                ],
                class_name="+ mt-2",
            )
        ]

    unapplied_changes = await ProfileFile.filter(profile=profile, created_at__gt=profile.updated_at).count()

    action_mode = None
    if mode is not None and target_obj is not None:
        action_form = []
        action_title = ""
        btn_text = ""
        btn_class = ""

        hidden_fields = [
            HiddenInput(
                name="file_loc",
                value=str(file_loc.value if file_loc is not None else -1),
            ),
            HiddenInput(
                name="target_type",
                value=str(target_type),
            ),
            HiddenInput(
                name="target",
                value=target,
            ),
            HiddenInput(
                name="dir_type",
                required=False,
                value=dir_type,
            ),
            HiddenInput(
                name="dir_prefix",
                required=False,
                value=dir_prefix,
            ),
        ]

        if mode == "rename":
            action_title = f"Renaming {target_obj.name}"
            btn_text = "Rename"
            btn_class = "btn-warning"

            action_form = [
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="name",
                            title="Name",
                            required=True,
                            initial=target_obj.name.rstrip('/'),
                        ),
                        *hidden_fields,
                    ],
                    loading=[c.Spinner(text="Editing...")],
                    submit_url=f"{profile_prefix_api}/files/rename",
                    submit_trigger=PageEvent(name="action-form-submit"),
                    footer=[],
                )
            ]

        elif mode == "delete":
            action_title = f"Deleting {target_obj.name}"
            btn_text = "Delete"
            btn_class = "btn-danger"

            action_form = [
                c.Heading(
                    text="Are you sure you want to delete this file/directory?",
                    level=5,
                    class_name="text-danger",
                ),
                c.Form(
                    form_fields=hidden_fields,
                    loading=[c.Spinner(text="Deleting...")],
                    submit_url=f"{profile_prefix_api}/files/delete",
                    submit_trigger=PageEvent(name="action-form-submit"),
                    footer=[],
                )
            ]

        if target_type == "dir":
            target_prefix = os.path.relpath(os.path.normpath(os.path.join("/", f"{dir_prefix}/{target_obj.name}")), "/")
            files_count = await ProfileFile.filter(
                profile=profile, location=file_loc, action__not=ProfileFileAction.DELETE,
                parent__startswith=target_prefix,
            ).count()
            action_form.append(c.Text(text=f"~{files_count} files will be affected"))

        action_mode = ActionMode(
            class_name="border-bottom mb-4 pb-3",
            components=[
                c.Heading(
                    text=action_title,
                    level=4,
                ),
                *action_form,
                c.Div(
                    class_name="modal-footer",
                    components=[
                        c.Button(
                            text="Cancel",
                            named_style="secondary",
                            on_click=GoToEvent(url=f"{profile_prefix}?dir_type={dir_type}&dir_prefix={dir_prefix}")
                        ),
                        c.Button(
                            text=btn_text,
                            on_click=PageEvent(name="action-form-submit"),
                            class_name=f"+ ms-2 {btn_class}",
                        )
                    ]
                ),
            ]
        )
    elif unapplied_changes:
        hidden_fields = [
            HiddenInput(
                name="dir_type",
                required=False,
                value=dir_type,
            ),
            HiddenInput(
                name="dir_prefix",
                required=False,
                value=dir_prefix,
            ),
        ]

        action_mode = ActionMode(
            class_name="border-bottom mb-4 pb-3",
            components=[
                c.Heading(
                    text=f"This profile has approximately {unapplied_changes} unapplied files (private changes)",
                    level=4,
                ),
                c.ServerLoad(
                    path=f"/admin/profiles/{profile.id}/unapplied-files",
                    load_trigger=PageEvent(name="load-unapplied-files"),
                    components=[
                        c.Link(
                            on_click=PageEvent(name="load-unapplied-files"),
                            components=[
                                c.Text(text="Show changes")
                            ],
                        )
                    ]
                ),
                c.Heading(
                    text="Do you want to apply them now?",
                    level=5,
                ),
                c.Form(
                    form_fields=hidden_fields,
                    loading=[c.Spinner(text="Applying...")],
                    submit_url=f"{profile_prefix_api}/apply-files",
                    submit_trigger=PageEvent(name="apply-form-submit"),
                    footer=[],
                ),
                c.Form(
                    form_fields=hidden_fields,
                    loading=[c.Spinner(text="Reverting...")],
                    submit_url=f"{profile_prefix_api}/revert-files",
                    submit_trigger=PageEvent(name="revert-form-submit"),
                    footer=[],
                ),
                c.Div(
                    class_name="modal-footer",
                    components=[
                        c.Button(
                            text="Apply",
                            on_click=PageEvent(name="apply-form-submit"),
                            class_name=f"+ btn-warning",
                        ),
                        c.Button(
                            text="Revert",
                            on_click=PageEvent(name="revert-form-submit"),
                            class_name=f"+ ms-2 btn-danger",
                        )
                    ]
                ),
            ]
        )

    ips_table = []
    if dir_type is None and mode is None:
        ips = await ProfileServerAddress.filter(profile=profile)
        ips_rows = [
            ips_table_row(profile.id, ip.id, ip.name, ip.ip)
            for ip in ips
        ]

        ips_head = c.Div(
            class_name="d-flex flex-row justify-content-between align-items-center my-2 py-2 border-top",
            components=[
                c.Heading(text="Addresses", level=4, class_name="+ "),
                c.Div(
                    components=[
                        c.Button(text="Add", on_click=PageEvent(name="address-modal")),
                    ],
                ),
            ]
        )

        if ips_rows:
            ips_table = [
                ips_head,
                c.Div(
                    components=[
                        ips_table_head(),
                        *ips_rows,
                    ]
                ),
            ]
        else:
            ips_table = [
                ips_head,
                c.Heading(text="No addresses added yet", level=5),
            ]

    profile = await ProfilePydantic.from_tortoise_orm(profile)
    return make_page(
        profile.name,
        action_mode,

        c.Link(components=[c.Text(text="<- Back")], on_click=GoToEvent(url=f"{PREFIX}/profiles")),
        c.Details(
            data=profile,
            fields=[
                DisplayLookup(field="id"),
                DisplayLookup(field="name"),
                DisplayLookup(field="description"),
                DisplayLookup(field="created_at"),
                DisplayLookup(field="updated_at"),
                DisplayLookup(field="public"),
            ]
        ),
        c.Div(
            class_name="pb-2 mb-2 border-bottom",
            components=[
                c.Button(
                    text="Edit", on_click=PageEvent(name="edit-modal")
                ),
                c.Button(
                    text="Upload manifest", on_click=PageEvent(name="manifest-modal"), class_name="+ ms-2",
                ),
            ]),

        *files_table,

        *ips_table,

        c.Modal(
            title="Edit profile",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="name",
                            title="Name",
                            required=True,
                            initial=profile.name,
                        ),
                        f.FormFieldTextarea(
                            name="description",
                            title="Description",
                            required=True,
                            initial=profile.description,
                        ),
                        f.FormFieldBoolean(
                            name="public",
                            title="Public",
                            required=False,
                            initial=profile.public,
                        ),
                    ],
                    loading=[c.Spinner(text="Editing...")],
                    submit_url=profile_prefix_api,
                    submit_trigger=PageEvent(name="edit-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="edit-modal", clear=True)
                ),
                c.Button(
                    text="Submit", on_click=PageEvent(name="edit-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="edit-modal"),
        ),

        c.Modal(
            title="Upload manifest",
            body=[
                c.Text(text="This will also make all file changes available"),
                c.Form(
                    form_fields=[
                        c.FormFieldFile(
                            name="manifest",
                            title="Manifest",
                            accept=".json",
                            multiple=False,
                            required=True,
                        ),
                    ],
                    loading=[c.Spinner(text="Uploading...")],
                    submit_url=f"{profile_prefix_api}/manifest",
                    submit_trigger=PageEvent(name="manifest-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="manifest-modal", clear=True)
                ),
                c.Button(
                    text="Submit", on_click=PageEvent(name="manifest-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="manifest-modal"),
        ),

        c.Modal(
            title="Upload file",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="directory",
                            title="Parent directory",
                            required=False,
                        ),
                        c.FormFieldFile(
                            name="files",
                            title="File(s)",
                            multiple=True,
                            required=True,
                        ),
                        c.FormFieldInput(
                            title="",
                            name="file_loc",
                            html_type="hidden",
                            required=True,
                            initial=file_loc.value if file_loc is not None else -1,
                            class_name="d-none",
                        ),
                        c.FormFieldInput(
                            title="",
                            name="dir_type",
                            html_type="hidden",
                            required=False,
                            initial=dir_type,
                            class_name="d-none",
                        ),
                        c.FormFieldInput(
                            title="",
                            name="dir_prefix",
                            html_type="hidden",
                            required=False,
                            initial=dir_prefix,
                            class_name="d-none",
                        ),
                    ],
                    loading=[c.Spinner(text="Uploading...")],
                    submit_url=f"{profile_prefix_api}/files",
                    submit_trigger=PageEvent(name="file-upload-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="file-upload-modal", clear=True)
                ),
                c.Button(
                    text="Upload", on_click=PageEvent(name="file-upload-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="file-upload-modal"),
        ),

        c.Modal(
            title="Add address",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="name",
                            title="Name",
                            required=True,
                        ),
                        f.FormFieldInput(
                            name="address",
                            title="Address",
                            required=True,
                        ),
                        HiddenInput(
                            name="profile_id",
                            value=profile.id,
                            required=True,
                        ),
                    ],
                    loading=[c.Spinner(text="Adding...")],
                    submit_url=f"{profile_prefix_api}/addresses",
                    submit_trigger=PageEvent(name="address-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="address-modal", clear=True)
                ),
                c.Button(
                    text="Add", on_click=PageEvent(name="address-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="address-modal"),
        ),
    )


@app_post_fastui("/api/admin/launcher-updates/")
@app_post_fastui("/api/admin/launcher-updates")
async def create_update(
        admin: User = Depends(admin_auth),
        code: int = Form(), name: str = Form(), changelog: str = Form(), os_type: UpdateOs = Form(),
        file: UploadFile = FormFile(accept=".zip", max_size=1024 * 1024 * 256),
):
    size = 0
    dir_id = uuid4()
    file.file.seek(0)

    s3_prefix = f"updates/{dir_id}"

    with ZipFile(file.file, "r") as zf:
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
        code=code,
        name=name,
        size=size,
        changelog=changelog,
        public=False,
        os=os_type,
        dir_id=dir_id,
    )

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/launcher-updates/{update.id}?{time()}"))]


@app_post_fastui("/api/admin/launcher-updates-auto/")
@app_post_fastui("/api/admin/launcher-updates-auto")
async def create_update_auto(
        admin: User = Depends(admin_auth),
        changelog: str = Form(), file: UploadFile = FormFile(accept=".zip", max_size=1024 * 1024 * 256),
):
    with ZipFile(file.file, "r") as zf:
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

    return await create_update(admin, code, name, changelog, os_type, file)


@app_post_fastui("/api/admin/launcher-updates/{update_id}/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/launcher-updates/{update_id}", dependencies=[Depends(admin_auth)])
async def edit_launcher_update(
        update_id: int,
        name: str = Form(), changelog: str = Form(), public: bool = Form(default=False),
):
    if (update := await LauncherUpdate.get_or_none(id=update_id)) is None:
        raise HTTPException(status_code=404, detail="Update not found")

    update.name = name
    update.changelog = changelog
    update.public = public
    await update.save(update_fields=["name", "changelog", "public"])

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/launcher-updates/{update.id}?{time()}"))]


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


@app_post_fastui("/api/admin/authlib-agent/")
@app_post_fastui("/api/admin/authlib-agent")
async def create_authlib_agent(
        admin: User = Depends(admin_auth),
        min_launcher_version: int = Form(default=None),
        file: UploadFile | None = FormFile(accept=".jar", max_size=1024 * 1024),
):
    if file is None or file.size == 0:
        prev_agent = await AuthlibAgent.filter().order_by("-id").first()
        if prev_agent is None:
            raise HTTPException(status_code=404, detail="There is no previous authlib agent available")
        file_size = prev_agent.size
        file_sha = prev_agent.sha1
        file_id = prev_agent.file_id
    else:
        file.file.seek(0)
        file_size = file.size
        file_sha = sha1(file.file.read()).hexdigest().lower()
        file_id = uuid4().hex

        file.file.seek(0)
        await S3.upload_object(S3_FILES_BUCKET, f"authlib-agent/{file_id}/{file_sha}", file.file)

    await AuthlibAgent.create(
        created_by=admin,
        size=file_size,
        sha1=file_sha,
        min_launcher_version=min_launcher_version,
        file_id=file_id,
    )

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/authlib-agent/?{time()}"))]


@app.get("/{path:path}")
async def html_landing() -> HTMLResponse:
    return HTMLResponse(prebuilt_html(title="WLands admin panel", api_root_url=PREFIX_API))


@app.exception_handler(NotAuthorized)
async def not_authorized_handler(request: Request, exc: NotAuthorized):
    resp = RedirectResponse(f"/admin/admin-new/login")
    resp.delete_cookie("auth_token")
    return resp
