import bcrypt
import pytest
from httpx import AsyncClient

from wlands.launcher.v1.app import max_attempts_per_time_window_password
from wlands.launcher.v1.request_models import LoginData
from wlands.launcher.v1.response_models import ErrorsResponse, AuthResponse
from wlands.models import User

TEST_NICKNAME = "test_user1"
TEST_EMAIL = f"{TEST_NICKNAME}@example.com"
TEST_PASSWORD = "test_passw0rd)"
TEST_PASSWORD_HASH = bcrypt.hashpw(TEST_PASSWORD.encode("utf8"), bcrypt.gensalt(4)).decode("utf8")

param_login = pytest.mark.parametrize(
    ("email", "login_email",),
    [
        (TEST_EMAIL, TEST_EMAIL,),
        (TEST_EMAIL, TEST_NICKNAME,),
    ],
    ids=[
        "email",
        "nickname",
    ],
)

@pytest.mark.parametrize(
    ("email",),
    [
        ("nonexistent@example.com",),
        ("nonexistent",),
    ],
    ids=[
        "email",
        "nickname",
    ],
)
@pytest.mark.asyncio
async def test_auth_nonexistent_user_fail(client: AsyncClient, email: str) -> None:
    response = await client.post("/launcher/v1/auth/login", json=LoginData(
        email="nonexistent@example.com", password="test_passw0rd",
    ).model_dump())
    assert response.status_code == 400
    resp = ErrorsResponse(**response.json())
    assert len(resp.errors) == 1
    assert "does not exists" in resp.errors[0]


@param_login
@pytest.mark.asyncio
async def test_auth_invalid_password_fail(client: AsyncClient, email: str, login_email: str) -> None:
    await User.create(
        email=email,
        nickname=email.split("@")[0],
        password=TEST_PASSWORD_HASH,
    )

    response = await client.post("/launcher/v1/auth/login", json=LoginData(
        email=login_email, password=f"_{TEST_PASSWORD}",
    ).model_dump())
    assert response.status_code == 400
    resp = ErrorsResponse(**response.json())
    assert len(resp.errors) == 1
    assert "does not exists" in resp.errors[0]


@param_login
@pytest.mark.asyncio
async def test_auth_login_success(client: AsyncClient, email: str, login_email: str) -> None:
    await User.create(
        email=email,
        nickname=email.split("@")[0],
        password=TEST_PASSWORD_HASH,
    )

    response = await client.post("/launcher/v1/auth/login", json=LoginData(
        email=login_email, password=TEST_PASSWORD,
    ).model_dump())
    assert response.status_code == 200
    resp = AuthResponse(**response.json())
    assert resp.token
    assert resp.refresh_token


@param_login
@pytest.mark.asyncio
async def test_auth_failed_attempts_exceeded(client: AsyncClient, email: str, login_email: str) -> None:
    await User.create(
        email=email,
        nickname=email.split("@")[0],
        password=TEST_PASSWORD_HASH,
    )

    for _ in range(max_attempts_per_time_window_password[0][1]):
        response = await client.post("/launcher/v1/auth/login", json=LoginData(
            email=login_email, password=f"_{TEST_PASSWORD}",
        ).model_dump())
        assert response.status_code == 400
        resp = ErrorsResponse(**response.json())
        assert len(resp.errors) == 1
        assert "does not exists" in resp.errors[0]

    response = await client.post("/launcher/v1/auth/login", json=LoginData(
        email=login_email, password=f"_{TEST_PASSWORD}",
    ).model_dump())
    assert response.status_code == 400
    resp = ErrorsResponse(**response.json())
    assert len(resp.errors) == 1
    assert "maximum number" in resp.errors[0]


@pytest.mark.parametrize(
    ("email", "login_email", "ban_reason",),
    [
        (TEST_EMAIL, TEST_EMAIL, None,),
        (TEST_EMAIL, TEST_NICKNAME, None,),
        (TEST_EMAIL, TEST_EMAIL, "test reason",),
        (TEST_EMAIL, TEST_NICKNAME, "test reason",),
    ],
    ids=[
        "email - no reason",
        "nickname - no reason",
        "email - reason",
        "nickname - reason",
    ],
)
@pytest.mark.asyncio
async def test_auth_user_banned(client: AsyncClient, email: str, login_email: str, ban_reason: str | None) -> None:
    await User.create(
        email=email,
        nickname=email.split("@")[0],
        password=TEST_PASSWORD_HASH,
        banned=True,
        ban_reason=ban_reason,
    )

    response = await client.post("/launcher/v1/auth/login", json=LoginData(
        email=login_email, password=TEST_PASSWORD,
    ).model_dump())
    assert response.status_code == 400
    resp = ErrorsResponse(**response.json())
    if ban_reason:
        assert len(resp.errors) == 2
    else:
        assert len(resp.errors) == 1

    assert "is banned" in resp.errors[0]
    if ban_reason:
        assert ban_reason in resp.errors[1]


@param_login
@pytest.mark.asyncio
async def test_auth_failed_attempts_not_exceeded(client: AsyncClient, email: str, login_email: str) -> None:
    await User.create(
        email=email,
        nickname=email.split("@")[0],
        password=TEST_PASSWORD_HASH,
    )

    for _ in range(max_attempts_per_time_window_password[0][1] - 1):
        response = await client.post("/launcher/v1/auth/login", json=LoginData(
            email=login_email, password=f"_{TEST_PASSWORD}",
        ).model_dump())
        assert response.status_code == 400
        resp = ErrorsResponse(**response.json())
        assert len(resp.errors) == 1
        assert "does not exists" in resp.errors[0]

    response = await client.post("/launcher/v1/auth/login", json=LoginData(
        email=login_email, password=TEST_PASSWORD,
    ).model_dump())
    assert response.status_code == 200
    resp = AuthResponse(**response.json())
    assert resp.token
    assert resp.refresh_token
