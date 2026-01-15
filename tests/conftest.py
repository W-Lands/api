from typing import AsyncGenerator

import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport

from wlands.main import app


@pytest_asyncio.fixture
async def app_with_lifespan() -> AsyncGenerator[FastAPI, None]:
    async with LifespanManager(app) as manager:
        yield manager.app


@pytest_asyncio.fixture
async def client(app_with_lifespan) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(transport=ASGITransport(app=app_with_lifespan), base_url="https://wlands.local") as client:
        yield client