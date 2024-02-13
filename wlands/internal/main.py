from bcrypt import gensalt, hashpw
from fastapi import FastAPI, Request, Header
from starlette.responses import JSONResponse
from tortoise.contrib.fastapi import register_tortoise
from tortoise.expressions import Q

from .schemas import CreateUser
from ..config import DATABASE_URL, INTERNAL_AUTH_TOKEN
from ..exceptions import CustomBodyException
from ..models import User, TgUser

app = FastAPI()

register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["wlands.models"]},
    generate_schemas=True,
    add_exception_handlers=False,
)


@app.exception_handler(CustomBodyException)
async def custom_exception_handler(request: Request, exc: CustomBodyException):
    return JSONResponse(status_code=exc.code, content=exc.body)


@app.post("/users/")
async def create_user(data: CreateUser, authorization: str | None = Header(default=None)):
    if authorization != INTERNAL_AUTH_TOKEN:
        raise CustomBodyException(401, {"error_message": "Wrong auth token"})

    if data.telegram_id is not None and await TgUser.filter(id=data.telegram_id).exists():
        raise CustomBodyException(400, {"error_message": "User with this telegram account already exists"})

    if await User.filter(Q(email=data.email) | Q(nickname=data.login)).exists():
        raise CustomBodyException(400, {"error_message": "User with this email or nickname already exists"})

    password = hashpw(data.password.encode("utf8"), gensalt()).decode("utf8")
    user = await User.create(email=data.email, nickname=data.login, password=password)
    if data.telegram_id is not None:
        await TgUser.create(id=data.telegram_id, user=user)

    return {"id": user.id}
