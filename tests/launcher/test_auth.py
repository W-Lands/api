import pytest
from httpx import AsyncClient

from wlands.launcher.v1.request_models import LoginData
from wlands.launcher.v1.response_models import ErrorsResponse


@pytest.mark.asyncio
async def test_auth_nonexistent_user_email(client: AsyncClient) -> None:
    response = await client.post("/launcher/v1/auth/login", json=LoginData(
        email="nonexistent@example.com", password="test_passw0rd",
    ).model_dump())
    assert response.status_code == 400
    resp = ErrorsResponse(**response.json())
    assert len(resp.errors) == 1
    assert "does not exists" in resp.errors[0]
