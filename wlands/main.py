from contextlib import asynccontextmanager
from os import environ

from fastapi import FastAPI, Request
from httpx import RemoteProtocolError
from starlette.responses import JSONResponse
from tortoise import generate_config
from tortoise.contrib.fastapi import RegisterTortoise

from . import minecraft, launcher, admin
from .config import DATABASE_URL, S3, S3_FILES_BUCKET, ROOT_PATH
from .exceptions import CustomBodyException


@asynccontextmanager
async def migrate_and_connect_orm(app_: FastAPI):
    if environ.get("SET_UPDATES_BUCKET_POLICY") == "1":
        policy_retries = 5
        for i in range(policy_retries):
            try:
                await S3.put_bucket_policy(S3_FILES_BUCKET, {
                    'Version': '2012-10-17',
                    'Statement': [{
                        'Effect': 'Allow',
                        'Principal': {'AWS': ['*']},
                        'Action': ['s3:GetObject'],
                        'Resource': [f'arn:aws:s3:::{S3_FILES_BUCKET}/*']
                    }]
                })
            except RemoteProtocolError:
                if i == policy_retries - 1:
                    raise

                from asyncio import sleep
                await sleep(3)

    orm_config = generate_config(DATABASE_URL, app_modules={"models": ["wlands.models", "aerich.models"]})
    async with RegisterTortoise(app=app_, config=orm_config, generate_schemas=True):
        yield


app = FastAPI(lifespan=migrate_and_connect_orm, openapi_url=None)
app.mount("/minecraft", minecraft.app)
app.mount("/launcher", launcher.app)
app.mount("/admin", admin.app)


@app.exception_handler(CustomBodyException)
@minecraft.app.exception_handler(CustomBodyException)
@launcher.app.exception_handler(CustomBodyException)
async def custom_exception_handler(request: Request, exc: CustomBodyException):
    return JSONResponse(status_code=exc.code, content=exc.body)


@app.get("/health")
async def healthcheck():
    return "ok"
