import os
from datetime import datetime
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
from fastui.forms import fastui_form, FormFile
from pydantic import BaseModel, EmailStr, Field, SecretStr
from pytz import UTC
from starlette.responses import HTMLResponse, JSONResponse

from wlands.admin.dependencies import admin_opt_auth, NotAuthorized, admin_auth
from wlands.config import S3
from wlands.launcher.manifest_models import VersionManifest
from wlands.models import User, UserSession, UserPydantic, GameSession, ProfilePydantic, GameProfile, ProfileFile, \
    ProfileFileType

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
                DisplayLookup(field="id", on_click=GoToEvent(url=f"{PREFIX}/profiles/{{id}}/")),
                DisplayLookup(field="name"),
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
async def create_profiile(
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
    db_type: ProfileFileType


@app_post_fastui("/api/admin/profiles/{profile_id}/files/", dependencies=[Depends(admin_auth)])
@app_post_fastui("/api/admin/profiles/{profile_id}/files", dependencies=[Depends(admin_auth)])
async def upload_profile_files(
        profile_id: int,
        directory: str | None = Form(default=None), file_type: ProfileFileType = Form(), dir_type: str | None = Form(),
        dir_prefix: str = Form(default=""),
        files: list[UploadFile] = FormFile(max_size=128 * 1024 * 1024),
):
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    files_to_create = []
    files_to_update = []
    for file in files:
        file.file.seek(0)
        sha = sha1()
        sha.update(file.file.read())
        sha = sha.hexdigest().lower()

        path = f"{dir_prefix}/{directory}/{file.filename}".replace("\\", "/")
        name = os.path.relpath(os.path.normpath(os.path.join("/", path)), "/")

        existing = await ProfileFile.get_or_none(profile=profile, type=file_type, name=name)
        if existing is not None and existing.sha1 == sha and existing.size == file.size:
            continue

        file.file.seek(0)
        file_id = uuid4().hex
        await S3.upload_object("wlands-profiles", f"files/{file_id}/{sha}", file.file)

        if existing is not None:
            existing.sha1 = sha
            existing.size = file.size
            existing.deleted = True
            files_to_update.append(existing)
        else:
            files_to_create.append(ProfileFile(
                profile=profile,
                type=file_type,
                name=name,
                sha1=sha,
                size=file.size,
                file_id=file_id,
            ))

    await ProfileFile.bulk_create(files_to_create)

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
            return cls(
                id=-1,
                created_at_fmt="",
                name=name,
                file_id="",
                sha1="",
                size=-1,
                url=f"{profile_prefix}?dir_type={dir_type}&dir_prefix={dir_prefix}/{name}",
                size_fmt="",
                action_rename_url=f"{profile_prefix}{ctx_prefix}&mode=rename&target_type=dir&target={name}",
                action_delete_url=f"{profile_prefix}{ctx_prefix}&mode=delete&target_type=dir&target={name}",
            )

        size_fmt = f"{file.size} B"
        if file.size > 1024 * 1024 * 1024:
            size_fmt = f"{file.size / 1024 / 1024 / 1024:.2f} GB"
        elif file.size > 1024 * 1024:
            size_fmt = f"{file.size / 1024 / 1024:.2f} MB"
        elif file.size > 1024:
            size_fmt = f"{file.size / 1024:.2f} KB"

        return cls(
            id=file.id,
            created_at_fmt=file.created_at.strftime("%d.%m.%Y %H:%M:%S"),
            name=name,
            file_id=file.file_id,
            sha1=file.sha1,
            size=file.size,
            url=file.url,
            size_fmt=size_fmt,
            action_rename_url=f"{profile_prefix}{ctx_prefix}&mode=rename&target_type=file&target={file.id}",
            action_delete_url=f"{profile_prefix}{ctx_prefix}&mode=delete&target_type=file&target={file.id}",
        )


profile_dirs: dict[str, ProfileTabLink] = {
    "game_dir": ProfileTabLink(type="game_dir", name="<Game Directory>", db_type=ProfileFileType.GAME),
    "profile_dir": ProfileTabLink(type="profile_dir", name="<Profile Directory>", db_type=ProfileFileType.PROFILE),
}


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

    file_type: ProfileFileType | None = None

    dir_prefix = dir_prefix.strip()
    dir_prefix = os.path.relpath(os.path.normpath(os.path.join("/", dir_prefix)), "/")
    if dir_prefix == ".":
        dir_prefix = ""

    target_obj = None

    if dir_type in profile_dirs:
        prof_dir = profile_dirs[dir_type]
        file_type = prof_dir.db_type

        files = await ProfileFile.filter(
            profile=profile, type=file_type, deleted=False, name__startswith=dir_prefix,
        ).order_by("name")

        vdirs = {}
        vfiles = []

        for file in files:
            file_path = file.name[len(dir_prefix):].lstrip("/")

            paths = file_path.split("/")
            if len(paths) > 1:
                if paths[0] not in vdirs:
                    name = f"{paths[0]}/"
                    vdirs[paths[0]] = ProfileFileV.from_db(None, name, dir_type, dir_prefix, profile.id)
                    if target_type == "dir" and target == name:
                        target_obj = vdirs[paths[0]]

                continue

            vfiles.append(ProfileFileV.from_db(file, file_path, dir_type, dir_prefix))
            if target_type == "file" and target == str(file.id):
                target_obj = vfiles[-1]

        vfiles = [*sorted(list(vdirs.values()), key=lambda e: e.name), *sorted(vfiles, key=lambda e: e.name)]

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
                    DisplayLookup(field="created_at_fmt", title="Created At"),
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

    action_mode = None
    if mode is not None and target_obj is not None:
        action_form = []
        action_title = ""
        btn_text = ""
        btn_class = ""

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
                            initial=target_obj.name,
                        ),
                    ],
                    loading=[c.Spinner(text="Editing...")],
                    submit_url="",  # TODO
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
                    form_fields=[
                    ],
                    loading=[c.Spinner(text="Editing...")],
                    submit_url="",  # TODO
                    submit_trigger=PageEvent(name="action-form-submit"),
                    footer=[],
                )
            ]

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
                            name="file_type",
                            html_type="hidden",
                            required=True,
                            initial=file_type.value if file_type is not None else -1,
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


@app.get("/{path:path}")
async def html_landing() -> HTMLResponse:
    return HTMLResponse(prebuilt_html(title="WLands admin panel", api_root_url=PREFIX_API))


@app.exception_handler(NotAuthorized)
async def custom_exception_handler(request: Request, exc: ...):
    return JSONResponse([c.FireEvent(event=GoToEvent(url=f"{PREFIX}/login")).model_dump()])
