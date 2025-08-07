from os import environ
from pathlib import Path

from aerich import Command
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse
from tortoise import Tortoise
from tortoise.contrib.fastapi import register_tortoise

from . import minecraft, launcher, admin
from .config import DATABASE_URL, S3, MIGRATIONS_DIR, S3_FILES_BUCKET
from .exceptions import CustomBodyException

app = FastAPI()
app.mount("/minecraft", minecraft.app)
app.mount("/launcher", launcher.app)
app.mount("/admin", admin.app)


@app.on_event("startup")
async def migrate_orm():
    command = Command({
        "connections": {"default": DATABASE_URL},
        "apps": {"models": {"models": ["wlands.models", "aerich.models"], "default_connection": "default"}},
    }, location=MIGRATIONS_DIR)
    await command.init()
    if Path(MIGRATIONS_DIR).exists():
        await command.migrate()
        await command.upgrade(True)
    else:
        await command.init_db(True)
    await Tortoise.close_connections()


register_tortoise(
    app,
    db_url=DATABASE_URL,
    modules={"models": ["wlands.models"]},
    generate_schemas=True,
    add_exception_handlers=False,
)


@app.on_event("startup")
async def on_startup():
    if environ.get("SET_UPDATES_BUCKET_POLICY") == "1":
        await S3.put_bucket_policy(S3_FILES_BUCKET, {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'AWS': ['*']},
                'Action': ['s3:GetObject'],
                'Resource': [f'arn:aws:s3:::{S3_FILES_BUCKET}/*']
            }]
        })


@app.exception_handler(CustomBodyException)
@minecraft.app.exception_handler(CustomBodyException)
@launcher.app.exception_handler(CustomBodyException)
async def custom_exception_handler(request: Request, exc: CustomBodyException):
    return JSONResponse(status_code=exc.code, content=exc.body)
