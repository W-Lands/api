import os
from datetime import datetime, timezone
from functools import partial
from hashlib import sha1
from time import time
from typing import Self, Literal
from uuid import UUID, uuid4

from bcrypt import checkpw, hashpw, gensalt
from fastapi import FastAPI, Depends, Request, HTTPException, Form, UploadFile
from fastui import prebuilt_html, FastUI, AnyComponent, components as c
from fastui.components import forms as f
from fastui.components.display import DisplayLookup
from fastui.events import GoToEvent, AuthEvent, PageEvent
from fastui.forms import fastui_form, FormFile, SelectOption
from pydantic import BaseModel, EmailStr, Field, SecretStr
from pytz import UTC
from starlette.responses import HTMLResponse, JSONResponse
from tortoise.expressions import Q

from wlands.admin.dependencies import admin_opt_auth, NotAuthorized, admin_auth
from wlands.config import S3
from wlands.launcher.manifest_models import VersionManifest
from wlands.models import User, UserSession, UserPydantic, GameSession, ProfilePydantic, GameProfile, ProfileFile, \
    ProfileFileLoc, ProfileFileAction, LauncherUpdate, LauncherUpdatePydantic, UpdateOs, LauncherAnnouncement, \
    LauncherAnnouncementPydantic, AnnouncementOs, AuthlibAgent, AuthlibAgentPydantic

PREFIX = "/admin"
PREFIX_API = f"{PREFIX}/api"
app = FastAPI()
app_get_fastui = partial(app.get, response_model=FastUI, response_model_exclude_none=True)
app_post_fastui = partial(app.post, response_model=FastUI, response_model_exclude_none=True)


class LoginForm(BaseModel):
    email: EmailStr = Field(title='Email Address', json_schema_extra={'autocomplete': 'email'})
    password: SecretStr = Field(title='Password', json_schema_extra={'autocomplete': 'password'})


@app_get_fastui("/api/admin/login/")
@app_get_fastui("/api/admin/login")
def admin_login(user: User | None = Depends(admin_opt_auth)) -> list[AnyComponent]:
    if user is not None:
        return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/users"))]

    return [
        c.Page(
            components=[
                c.Heading(text='Login', level=3),
                c.ModelForm(model=LoginForm, submit_url=f"{PREFIX_API}/admin/login", display_mode='page'),
            ]
        )
    ]


@app_post_fastui("/api/admin/login/")
@app_post_fastui("/api/admin/login")
async def admin_login_post(form: LoginForm = fastui_form(LoginForm)) -> list[AnyComponent]:
    if (user := await User.get_or_none(email=form.email, admin=True, banned=False)) is None:
        raise HTTPException(status_code=400, detail="Wrong credentials.")

    if not checkpw(form.password.get_secret_value().encode(), user.password.encode()):
        raise HTTPException(status_code=400, detail="Wrong credentials.")

    session = await UserSession.create(user=user)

    return [
        c.FireEvent(
            event=AuthEvent(
                token=f"{user.id.hex}{session.id.hex}{session.token}",
                url=f"{PREFIX}/users"
            )
        )
    ]


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


@app_get_fastui("/api/admin/users/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/users", dependencies=[Depends(admin_auth)])
async def users_table(page: int = 1) -> list[AnyComponent]:
    PAGE_SIZE = 25

    users = [
        await UserPydantic.from_tortoise_orm(user)
        for user in await User.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("id")
    ]

    return make_page(
        "Users",

        c.Button(text="Create user", on_click=PageEvent(name="create-modal"), class_name="+ mb-2 mt-2"),
        c.Table(
            data=users,
            data_model=UserPydantic,
            columns=[
                DisplayLookup(field="id", on_click=GoToEvent(url=f"{PREFIX}/users/{{id}}/")),
                DisplayLookup(field="email"),
                DisplayLookup(field="nickname"),
                DisplayLookup(field="banned"),
            ],
        ),
        c.Pagination(page=page, page_size=PAGE_SIZE, total=await User.filter().count()),

        c.Modal(
            title="Create user",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="nickname",
                            title="Nickname",
                            required=True,
                        ),
                        c.FormFieldInput(
                            name="password",
                            title="Password",
                            html_type="password",
                            required=True,
                        ),
                    ],
                    loading=[c.Spinner(text="Creating user...")],
                    submit_url=f"{PREFIX_API}/admin/users",
                    submit_trigger=PageEvent(name="create-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="create-modal", clear=True)
                ),
                c.Button(
                    text="Create", on_click=PageEvent(name="create-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="create-modal"),
        ),
    )


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


@app_get_fastui("/api/admin/users/{user_id}/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/users/{user_id}", dependencies=[Depends(admin_auth)])
async def user_info(user_id: UUID) -> list[AnyComponent]:
    if (user := await User.get_or_none(id=user_id)) is None:
        raise HTTPException(status_code=404, detail="User not found")

    ban_unban = "Unban" if user.banned else "Ban"

    user = await UserPydantic.from_tortoise_orm(user)
    return make_page(
        user.nickname,

        c.Link(components=[c.Text(text="<- Back")], on_click=GoToEvent(url=f"{PREFIX}/users")),
        c.Details(data=user, fields=[
            DisplayLookup(field="id"),
            DisplayLookup(field="email"),
            DisplayLookup(field="nickname"),
            DisplayLookup(field="signed_for_beta"),
            DisplayLookup(field="banned"),
            DisplayLookup(field="admin"),
            DisplayLookup(field="has_mfa"),
        ]),
        c.Div(components=[
            c.Button(
                text=ban_unban, named_style="warning", on_click=PageEvent(name="ban-modal")
            ),
            c.Button(
                text="Edit", on_click=PageEvent(name="edit-modal"), class_name="+ ms-2",
            ),
        ]),
        c.Modal(
            title="Edit user",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="nickname",
                            title="Nickname",
                            initial=user.nickname,
                            required=True,
                        ),
                    ],
                    loading=[c.Spinner(text="Editing...")],
                    submit_url=f"{PREFIX_API}/admin/users/{user.id}",
                    submit_trigger=PageEvent(name="edit-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="edit-form", clear=True)
                ),
                c.Button(
                    text="Submit", on_click=PageEvent(name="edit-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="edit-modal"),
        ),
        c.Modal(
            title=f"{ban_unban} user?",
            body=[
                c.Paragraph(text="Are you sure you want to ban this user?"),
                c.Form(
                    form_fields=[],
                    loading=[c.Spinner(text="...")],
                    submit_url=f"{PREFIX_API}/admin/users/{user.id}/{ban_unban}",
                    submit_trigger=PageEvent(name="ban-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="ban-form", clear=True)
                ),
                c.Button(
                    text=ban_unban, on_click=PageEvent(name="ban-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="ban-modal"),
        ),
    )


@app_get_fastui("/api/admin/profiles/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/profiles", dependencies=[Depends(admin_auth)])
async def profiles_table(page: int = 1) -> list[AnyComponent]:
    PAGE_SIZE = 25

    profiles = [
        await ProfilePydantic.from_tortoise_orm(profile)
        for profile in await GameProfile.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("id")
    ]

    return make_page(
        "Profiles",

        c.Button(text="Create profile", on_click=PageEvent(name="create-modal"), class_name="+ mb-2 mt-2"),
        c.Table(
            data=profiles,
            data_model=ProfilePydantic,
            columns=[
                DisplayLookup(field="id"),
                DisplayLookup(field="name", on_click=GoToEvent(url=f"{PREFIX}/profiles/{{id}}/")),
                DisplayLookup(field="created_at"),
                DisplayLookup(field="updated_at"),
                DisplayLookup(field="public"),
            ],
        ),
        c.Pagination(page=page, page_size=PAGE_SIZE, total=await GameProfile.filter().count()),

        c.Modal(
            title="Create profile",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="name",
                            title="Name",
                            required=True,
                        ),
                        f.FormFieldTextarea(
                            name="description",
                            title="Description",
                            required=True,
                        ),
                        c.FormFieldFile(
                            name="manifest",
                            title="Manifest",
                            accept=".json",
                            multiple=False,
                            required=True,
                        ),
                        f.FormFieldBoolean(
                            name="public",
                            title="Public",
                            initial=False,
                        ),
                    ],
                    loading=[c.Spinner(text="Creating profile...")],
                    submit_url=f"{PREFIX_API}/admin/profiles",
                    submit_trigger=PageEvent(name="create-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="create-modal", clear=True)
                ),
                c.Button(
                    text="Create", on_click=PageEvent(name="create-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="create-modal"),
        ),
    )


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


class ProfileTabLink(BaseModel):
    type: str
    name: str
    db_type: ProfileFileLoc


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
        await S3.upload_object("wlands-profiles", f"files/{file_id}/{sha}", file.file)

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


def format_size(size: int) -> str:
    if size > 1024 * 1024 * 1024:
        return f"{size / 1024 / 1024 / 1024:.2f} GB"
    elif size > 1024 * 1024:
        return f"{size / 1024 / 1024:.2f} MB"
    elif size > 1024:
        return f"{size / 1024:.2f} KB"
    return f"{size} B"


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


profile_dirs: dict[str, ProfileTabLink] = {
    "game_dir": ProfileTabLink(type="game_dir", name="<Game Directory>", db_type=ProfileFileLoc.GAME),
    "profile_dir": ProfileTabLink(type="profile_dir", name="<Profile Directory>", db_type=ProfileFileLoc.PROFILE),
}


def HiddenInput(*, name: str, value: str, required: bool = True) -> c.FormFieldInput:
    return c.FormFieldInput(
        name=name,
        initial=value,
        html_type="hidden",
        required=required,
        class_name="d-none",
        title="",
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
            class_name="pb-4 border-bottom",
            components=[
                c.Button(
                    text="Edit", on_click=PageEvent(name="edit-modal")
                ),
                c.Button(
                    text="Upload manifest", on_click=PageEvent(name="manifest-modal"), class_name="+ ms-2",
                ),
            ]),

        *files_table,

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
    )


@app_post_fastui("/api/admin/launcher-updates/")
@app_post_fastui("/api/admin/launcher-updates")
async def create_update(
        admin: User = Depends(admin_auth),
        code: int = Form(), name: str = Form(), changelog: str = Form(), os_type: UpdateOs = Form(),
        file: UploadFile = FormFile(accept=".msi,.exe", max_size=1024 * 1024 * 256),
):
    file.file.seek(0)
    sha = sha1()
    sha.update(file.file.read())
    sha = sha.hexdigest().lower()

    file.file.seek(0)
    await S3.upload_object("wlands-profiles", f"updates/{sha}", file.file)

    update = await LauncherUpdate.create(
        created_by=admin,
        code=code,
        name=name,
        sha1=sha,
        size=file.size,
        changelog=changelog,
        public=False,
        os=os_type,
    )

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/launcher-updates/{update.id}?{time()}"))]


@app_get_fastui("/api/admin/launcher-updates/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/launcher-updates", dependencies=[Depends(admin_auth)])
async def launcher_updates_table(page: int = 1) -> list[AnyComponent]:
    PAGE_SIZE = 25

    updates = [
        await LauncherUpdatePydantic.from_tortoise_orm(update)
        for update in await LauncherUpdate.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("-id")
    ]

    return make_page(
        "Updates",

        c.Button(text="Create update", on_click=PageEvent(name="create-modal"), class_name="+ mb-2 mt-2"),
        c.Table(
            data=updates,
            data_model=LauncherUpdatePydantic,
            columns=[
                DisplayLookup(field="id"),
                DisplayLookup(field="code"),
                DisplayLookup(field="name", on_click=GoToEvent(url=f"{PREFIX}/launcher-updates/{{id}}/")),
                DisplayLookup(field="created_at"),
                DisplayLookup(field="size"),
                DisplayLookup(field="public"),
            ],
        ),
        c.Pagination(page=page, page_size=PAGE_SIZE, total=await LauncherUpdate.filter().count()),

        c.Modal(
            title="Create update",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="code",
                            title="Code",
                            html_type="number",
                            required=True,
                        ),
                        c.FormFieldInput(
                            name="name",
                            title="Name",
                            required=True,
                        ),
                        f.FormFieldTextarea(
                            name="changelog",
                            title="Changelog",
                            required=True,
                        ),
                        f.FormFieldSelect(
                            name="os_type",
                            title="Os",
                            options=[
                                SelectOption(value=str(UpdateOs.WINDOWS.value), label="Windows"),
                                SelectOption(value=str(UpdateOs.LINUX.value), label="Linux"),
                            ],
                            required=True,
                        ),
                        c.FormFieldFile(
                            name="file",
                            title="Installer file",
                            accept=".msi,.exe",
                            multiple=False,
                            required=True,
                        ),
                    ],
                    loading=[c.Spinner(text="Creating update...")],
                    submit_url=f"{PREFIX_API}/admin/launcher-updates",
                    submit_trigger=PageEvent(name="create-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="create-modal", clear=True)
                ),
                c.Button(
                    text="Create", on_click=PageEvent(name="create-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="create-modal"),
        ),
    )


@app_post_fastui("/api/admin/launcher-updates/{update_id}/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/launcher-updates/{update_id}", dependencies=[Depends(admin_auth)])
async def edit_launcher_update(
        update_id: int,
        changelog: str = Form(), public: bool = Form(default=False),
):
    if (update := await LauncherUpdate.get_or_none(id=update_id)) is None:
        raise HTTPException(status_code=404, detail="Update not found")

    update.changelog = changelog
    update.public = public
    await update.save(update_fields=["changelog", "public"])

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/launcher-updates/{update.id}?{time()}"))]


@app_get_fastui("/api/admin/launcher-updates/{update_id}/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/launcher-updates/{update_id}", dependencies=[Depends(admin_auth)])
async def launcher_update_info(update_id: int) -> list[AnyComponent]:
    if (update := await LauncherUpdate.get_or_none(id=update_id)) is None:
        raise HTTPException(status_code=404, detail="Update not found")

    update_pd = await LauncherUpdatePydantic.from_tortoise_orm(update)
    return make_page(
        update.name,

        c.Link(components=[c.Text(text="<- Back")], on_click=GoToEvent(url=f"{PREFIX}/launcher-updates")),
        c.Details(data=update_pd, fields=[
            DisplayLookup(field="id"),
            DisplayLookup(field="code"),
            DisplayLookup(field="created_at"),
            DisplayLookup(field="sha1"),
            c.Display(title="Size", value=format_size(update.size)),
            DisplayLookup(field="public"),
            c.Display(title="Os", value=update.os.name.lower().title()),
            DisplayLookup(field="changelog"),
        ]),
        c.Div(components=[
            c.Button(
                text="Download", on_click=GoToEvent(url=update.url()),
            ),
            c.Button(
                text="Edit", on_click=PageEvent(name="edit-modal"), class_name="+ ms-2",
            ),
        ]),
        c.Modal(
            title="Edit update",
            body=[
                c.Form(
                    form_fields=[
                        f.FormFieldTextarea(
                            name="changelog",
                            title="Changelog",
                            initial=update.changelog,
                            required=True,
                        ),
                        c.FormFieldBoolean(
                            name="public",
                            title="Public",
                            initial=update.public,
                            required=False,
                        )
                    ],
                    loading=[c.Spinner(text="Editing...")],
                    submit_url=f"{PREFIX_API}/admin/launcher-updates/{update.id}",
                    submit_trigger=PageEvent(name="edit-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="edit-form", clear=True)
                ),
                c.Button(
                    text="Edit", on_click=PageEvent(name="edit-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="edit-modal"),
        ),
    )


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


@app_get_fastui("/api/admin/launcher-announcements/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/launcher-announcements", dependencies=[Depends(admin_auth)])
async def launcher_announcements_table(page: int = 1) -> list[AnyComponent]:
    PAGE_SIZE = 25

    announcements = [
        await LauncherAnnouncementPydantic.from_tortoise_orm(ann)
        for ann in await LauncherAnnouncement.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE).order_by("-id")
    ]

    return make_page(
        "Announcements",

        c.Button(text="Create announcement", on_click=PageEvent(name="create-modal"), class_name="+ mb-2 mt-2"),
        c.Table(
            data=announcements,
            data_model=LauncherAnnouncementPydantic,
            columns=[
                DisplayLookup(field="id"),
                DisplayLookup(field="name", on_click=GoToEvent(url=f"{PREFIX}/launcher-announcements/{{id}}/")),
                DisplayLookup(field="created_at"),
                DisplayLookup(field="active_from"),
                DisplayLookup(field="active_to"),
                DisplayLookup(field="onetime"),
            ],
        ),
        c.Pagination(page=page, page_size=PAGE_SIZE, total=await LauncherAnnouncement.filter().count()),

        c.Modal(
            title="Create announcement",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="name",
                            title="Name",
                            required=True,
                        ),
                        c.FormFieldInput(
                            name="active_from",
                            title="Active from",
                            html_type="datetime-local",
                            required=True,
                        ),
                        c.FormFieldInput(
                            name="active_to",
                            title="Active to",
                            html_type="datetime-local",
                            required=True,
                        ),
                        f.FormFieldSelect(
                            name="os_type",
                            title="Os",
                            options=[
                                SelectOption(value=str(AnnouncementOs.ALL.value), label="All"),
                                SelectOption(value=str(AnnouncementOs.WINDOWS.value), label="Windows"),
                                SelectOption(value=str(AnnouncementOs.LINUX.value), label="Linux"),
                            ],
                            required=True,
                        ),
                        f.FormFieldTextarea(
                            name="text",
                            title="Text",
                            required=True,
                        ),
                        c.FormFieldBoolean(
                            name="onetime",
                            title="Onetime",
                            required=False,
                            initial=True,
                        ),
                    ],
                    loading=[c.Spinner(text="Creating announcement...")],
                    submit_url=f"{PREFIX_API}/admin/launcher-announcements",
                    submit_trigger=PageEvent(name="create-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="create-modal", clear=True)
                ),
                c.Button(
                    text="Create", on_click=PageEvent(name="create-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="create-modal"),
        ),
    )


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


@app_get_fastui("/api/admin/launcher-announcements/{announcement_id}/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/launcher-announcements/{announcement_id}", dependencies=[Depends(admin_auth)])
async def launcher_announcement_info(announcement_id: int) -> list[AnyComponent]:
    if (announcement := await LauncherAnnouncement.get_or_none(id=announcement_id)) is None:
        raise HTTPException(status_code=404, detail="Announcement not found")

    announcement_pd = await LauncherAnnouncementPydantic.from_tortoise_orm(announcement)
    return make_page(
        announcement.name,

        c.Link(components=[c.Text(text="<- Back")], on_click=GoToEvent(url=f"{PREFIX}/launcher-announcements")),
        c.Details(data=announcement_pd, fields=[
            DisplayLookup(field="id"),
            DisplayLookup(field="created_at"),
            DisplayLookup(field="active_from"),
            DisplayLookup(field="active_to"),
            c.Display(title="Os", value=announcement.os.name.lower().title()),
            DisplayLookup(field="onetime"),
            DisplayLookup(field="text"),
        ]),
        c.Div(components=[
            c.Button(
                text="Edit", on_click=PageEvent(name="edit-modal"), class_name="+ ms-2",
            ),
        ]),
        c.Modal(
            title="Edit announcement",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            name="active_from",
                            title="Active from",
                            html_type="datetime-local",
                            required=True,
                            initial=announcement.active_from.strftime("%Y-%m-%dT%H:%M"),
                        ),
                        c.FormFieldInput(
                            name="active_to",
                            title="Active to",
                            html_type="datetime-local",
                            required=True,
                            initial=announcement.active_to.strftime("%Y-%m-%dT%H:%M"),
                        ),
                        f.FormFieldTextarea(
                            name="text",
                            title="Text",
                            initial=announcement.text,
                            required=True,
                        ),
                        c.FormFieldBoolean(
                            name="onetime",
                            title="Onetime",
                            initial=announcement.onetime,
                            required=False,
                        )
                    ],
                    loading=[c.Spinner(text="Editing...")],
                    submit_url=f"{PREFIX_API}/admin/launcher-announcements/{announcement.id}",
                    submit_trigger=PageEvent(name="edit-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="edit-form", clear=True)
                ),
                c.Button(
                    text="Edit", on_click=PageEvent(name="edit-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="edit-modal"),
        ),
    )


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
        await S3.upload_object("wlands-profiles", f"authlib-agent/{file_id}/{file_sha}", file.file)

    await AuthlibAgent.create(
        created_by=admin,
        size=file_size,
        sha1=file_sha,
        min_launcher_version=min_launcher_version,
        file_id=file_id,
    )

    return [c.FireEvent(event=GoToEvent(url=f"{PREFIX}/authlib-agent/?{time()}"))]


@app_get_fastui("/api/admin/authlib-agent/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/authlib-agent", dependencies=[Depends(admin_auth)])
async def authlib_agent_info() -> list[AnyComponent]:
    agent = await AuthlibAgent.filter().order_by("-id").first()
    agent_pydantic = await AuthlibAgentPydantic.from_tortoise_orm(agent) if agent is not None else None

    download_button = ()
    if agent is not None:
        download_button = (
            c.Button(
                text="Download current", on_click=GoToEvent(url=agent.url()), class_name="+ ms-2",
            ),
        )

    details = c.Heading(text="No authlib agent", level=3)
    if agent is not None:
        details = c.Details(
            data=agent_pydantic,
            fields=[
                DisplayLookup(field="id"),
                DisplayLookup(field="created_at"),
                DisplayLookup(field="size"),
                DisplayLookup(field="sha1"),
                DisplayLookup(field="min_launcher_version"),
            ],
        )

    return make_page(
        "Authlib Agent",


        details,
        c.Div(components=[
            c.Button(
                text="Upload new", on_click=PageEvent(name="upload-modal"),
            ),
            *download_button,
        ]),

        c.Modal(
            title="Upload/edit authlib agent",
            body=[
                c.Form(
                    form_fields=[
                        c.FormFieldInput(
                            html_type="number",
                            name="min_launcher_version",
                            title="Minimum launcher version",
                            required=True,
                            initial=str(agent.min_launcher_version) if agent is not None else "",
                        ),
                        c.FormFieldFile(
                            name="file",
                            title="Agent JAR file",
                            required=agent is None,
                            multiple=False,
                            accept=".jar",
                        ),
                    ],
                    loading=[c.Spinner(text="Creating announcement...")],
                    submit_url=f"{PREFIX_API}/admin/authlib-agent",
                    submit_trigger=PageEvent(name="upload-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="upload-modal", clear=True)
                ),
                c.Button(
                    text="Create", on_click=PageEvent(name="upload-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="upload-modal"),
        ),
    )


@app.get("/{path:path}")
async def html_landing() -> HTMLResponse:
    return HTMLResponse(prebuilt_html(title="WLands admin panel", api_root_url=PREFIX_API))


@app.exception_handler(NotAuthorized)
async def custom_exception_handler(request: Request, exc: ...):
    return JSONResponse([c.FireEvent(event=GoToEvent(url=f"{PREFIX}/login")).model_dump()])
