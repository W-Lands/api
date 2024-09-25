from functools import partial
from time import time
from uuid import UUID

from bcrypt import checkpw, hashpw, gensalt
from fastapi import FastAPI, Depends, Request, HTTPException, Form
from fastui import prebuilt_html, FastUI, AnyComponent, components as c
from fastui.components.display import DisplayLookup
from fastui.events import GoToEvent, AuthEvent, PageEvent
from fastui.forms import fastui_form
from pydantic import BaseModel, EmailStr, Field, SecretStr
from starlette.responses import HTMLResponse, JSONResponse

from wlands.admin.dependencies import admin_opt_auth, NotAuthorized, admin_auth
from wlands.models import User, UserSession, UserPydantic, GameSession

PREFIX = "/admin"
PREFIX_API = f"{PREFIX}/api"
app = FastAPI()
app_get_fastui = partial(app.get, response_model=FastUI, response_model_exclude_none=True)
app_post_fastui = partial(app.post, response_model=FastUI, response_model_exclude_none=True)


class LoginForm(BaseModel):
    email: EmailStr = Field(title='Email Address', json_schema_extra={'autocomplete': 'email'})
    password: SecretStr = Field(title='Password', json_schema_extra={'autocomplete': 'current-password'})


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


@app_get_fastui("/api/admin/users/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/users", dependencies=[Depends(admin_auth)])
async def users_table(page: int = 1) -> list[AnyComponent]:
    PAGE_SIZE = 25

    users = [
        await UserPydantic.from_tortoise_orm(user)
        for user in await User.filter().offset(PAGE_SIZE * (page - 1)).limit(PAGE_SIZE)
    ]

    return [
        c.Page(
            components=[
                c.Heading(text="Users", level=2),
                c.Button(text="Create user", on_click=PageEvent(name="create-modal")),
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
                            text="Create", on_click=PageEvent(name="create-form-submit")
                        ),
                    ],
                    open_trigger=PageEvent(name="create-modal"),
                ),
            ]
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


@app_get_fastui("/api/admin/users/{user_id}/", dependencies=[Depends(admin_auth)])
@app_get_fastui("/api/admin/users/{user_id}", dependencies=[Depends(admin_auth)])
async def user_info(user_id: UUID) -> list[AnyComponent]:
    if (user := await User.get_or_none(id=user_id)) is None:
        raise HTTPException(status_code=404, detail="User not found")

    ban_unban = "Unban" if user.banned else "Ban"

    user = await UserPydantic.from_tortoise_orm(user)
    return [
        c.Page(
            components=[
                c.Link(components=[c.Text(text="<- Back")], on_click=GoToEvent(url=f"{PREFIX}/users")),
                c.Heading(text=user.nickname, level=2),
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
                        text="Edit", on_click=PageEvent(name="edit-modal")
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
                            text="Submit", on_click=PageEvent(name="edit-form-submit")
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
                            text=ban_unban, on_click=PageEvent(name="ban-form-submit")
                        ),
                    ],
                    open_trigger=PageEvent(name="ban-modal"),
                ),
            ]
        ),
    ]


@app.get("/{path:path}")
async def html_landing() -> HTMLResponse:
    return HTMLResponse(prebuilt_html(title="WLands admin panel", api_root_url=PREFIX_API))


@app.exception_handler(NotAuthorized)
async def custom_exception_handler(request: Request, exc: ...):
    return JSONResponse([c.FireEvent(event=GoToEvent(url=f"{PREFIX}/login")).model_dump()])
