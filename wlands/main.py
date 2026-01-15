from contextlib import asynccontextmanager
from os import environ

from fastapi import FastAPI, Request
from httpx import RemoteProtocolError
from starlette.responses import JSONResponse, RedirectResponse
from tortoise import generate_config
from tortoise.contrib.fastapi import RegisterTortoise

from . import minecraft, launcher, admin
from .config import DATABASE_URL, S3, S3_FILES_BUCKET
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


app = FastAPI(
    lifespan=migrate_and_connect_orm,
    openapi_url=None,
    root_path=environ.get("ROOT_PATH", ""),
)
app.include_router(minecraft.router)
app.include_router(launcher.router)
app.include_router(admin.router)


@app.exception_handler(CustomBodyException)
async def custom_exception_handler(request: Request, exc: CustomBodyException):
    return JSONResponse(status_code=exc.code, content=exc.body)


@app.exception_handler(admin.NotAuthorized)
async def not_authorized_handler(request: Request, exc: admin.NotAuthorized):
    root_path = request.scope.get("root_path")
    resp = RedirectResponse(f"{root_path}{admin.router.prefix}/login")
    resp.delete_cookie("auth_token")
    return resp


@app.get("/health")
async def healthcheck():
    return "ok"
