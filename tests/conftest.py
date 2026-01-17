import asyncio
from typing import AsyncGenerator

import pytest_asyncio
import uvicorn
from aiofiles.tempfile import TemporaryDirectory
from asgi_lifespan import LifespanManager
from fake_s3.file_store import FileStore
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from fake_s3.main import app as s3_app

from wlands.main import app


@pytest_asyncio.fixture
async def app_with_lifespan() -> AsyncGenerator[FastAPI, None]:
    async with LifespanManager(app) as manager:
        yield manager.app


@pytest_asyncio.fixture
async def client(app_with_lifespan) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_with_lifespan), base_url="https://wlands.local") as client:
        yield client


@pytest_asyncio.fixture
async def fake_s3_server() -> AsyncGenerator[None, None]:
    async with TemporaryDirectory() as tempdir:
        storage = FileStore(tempdir)
        storage.create_bucket("wlands")
        storage.create_bucket("wlands-files")

        s3_app.config["store"] = storage
        config = uvicorn.Config(s3_app, host="127.0.0.1", port=60080, log_level="warning")
        server = uvicorn.Server(config=config)
        s3_task = asyncio.get_running_loop().create_task(server.serve())

        yield

        server.should_exit = True
        await asyncio.wait_for(s3_task, timeout=3)
