from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from tortoise.contrib.fastapi import register_tortoise

from . import minecraft
from . import launcher
from .config import DATABASE_URL
from .exceptions import CustomBodyException

app = FastAPI()
app.mount("/minecraft", minecraft.app)
app.mount("/launcher", launcher.app)

register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["wlands.models"]},
    generate_schemas=True,
    add_exception_handlers=False,
)


async def custom_exception_handler(request: Request, exc: CustomBodyException):
    return JSONResponse(status_code=exc.code, content=exc.body)


app.exception_handler(CustomBodyException)(custom_exception_handler)
minecraft.app.exception_handler(CustomBodyException)(custom_exception_handler)
launcher.app.exception_handler(CustomBodyException)(custom_exception_handler)

