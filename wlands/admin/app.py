from datetime import datetime
from functools import partial
from time import time
from uuid import UUID

from bcrypt import checkpw, hashpw, gensalt
from fastapi import FastAPI, Depends, Request, HTTPException, Form, UploadFile
from fastui import prebuilt_html, FastUI, AnyComponent, components as c
from fastui.components.display import DisplayLookup
from fastui.components import forms as f
from fastui.events import GoToEvent, AuthEvent, PageEvent
from fastui.forms import fastui_form, FormFile
from pydantic import BaseModel, EmailStr, Field, SecretStr
from pytz import UTC
from starlette.responses import HTMLResponse, JSONResponse

from wlands.admin.dependencies import admin_opt_auth, NotAuthorized, admin_auth
from wlands.launcher.manifest_models import VersionManifest
from wlands.models import User, UserSession, UserPydantic, GameSession, ProfilePydantic, GameProfile

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


def make_page(title: str, *components: AnyComponent) -> list[AnyComponent]:
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


@app_get_fastui("/api/admin/profiles/{profile_id}/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/profiles/{profile_id}", dependencies=[Depends(admin_auth)])
async def profile_info(profile_id: int) -> list[AnyComponent]:
    if (profile := await GameProfile.get_or_none(id=profile_id)) is None:
        raise HTTPException(status_code=404, detail="User not found")

    profile = await ProfilePydantic.from_tortoise_orm(profile)
    return make_page(
        profile.name,

        c.Link(components=[c.Text(text="<- Back")], on_click=GoToEvent(url=f"{PREFIX}/profiles")),
        c.Details(data=profile, fields=[
            DisplayLookup(field="id"),
            DisplayLookup(field="name"),
            DisplayLookup(field="description"),
            DisplayLookup(field="created_at"),
            DisplayLookup(field="updated_at"),
            DisplayLookup(field="public"),
        ]),
        c.Div(components=[
            c.Button(
                text="Edit", on_click=PageEvent(name="edit-modal")
            ),
            c.Button(
                text="Upload manifest", on_click=PageEvent(name="manifest-modal"), class_name="+ ms-2",
            ),
        ]),
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
                    submit_url=f"{PREFIX_API}/admin/profiles/{profile.id}",
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
                    submit_url=f"{PREFIX_API}/admin/profiles/{profile.id}/manifest",
                    submit_trigger=PageEvent(name="manifest-form-submit"),
                    footer=[],
                ),
            ],
            footer=[
                c.Button(
                    text="Cancel", named_style="secondary", on_click=PageEvent(name="manifest-form", clear=True)
                ),
                c.Button(
                    text="Submit", on_click=PageEvent(name="manifest-form-submit"), class_name="+ ms-2",
                ),
            ],
            open_trigger=PageEvent(name="manifest-modal"),
        ),
    )


@app.get("/{path:path}")
async def html_landing() -> HTMLResponse:
    return HTMLResponse(prebuilt_html(title="WLands admin panel", api_root_url=PREFIX_API))


@app.exception_handler(NotAuthorized)
async def custom_exception_handler(request: Request, exc: ...):
    return JSONResponse([c.FireEvent(event=GoToEvent(url=f"{PREFIX}/login")).model_dump()])
