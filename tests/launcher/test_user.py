import base64
from io import BytesIO

import pytest
from PIL import Image
from httpx import AsyncClient

from tests.launcher.data import TEST_EMAIL, TEST_NICKNAME, TEST_PASSWORD_HASH
from tests.launcher.utils import TokenAuth
from wlands.launcher.v1.request_models import PatchUserData
from wlands.launcher.v1.response_models import UserInfoResponse
from wlands.models import User, GameSession


@pytest.mark.asyncio
async def test_get_user_info(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)

    response = await client.get("/launcher/v1/users/me", auth=TokenAuth(session.make_token()))
    assert response.status_code == 200
    resp = UserInfoResponse(**response.json())
    assert resp.id == user.id
    assert resp.email == TEST_EMAIL
    assert resp.nickname == TEST_NICKNAME
    assert resp.skin is None
    assert resp.cape is None
    assert not resp.mfa
    assert not resp.admin


@pytest.mark.usefixtures("fake_s3_server")
@pytest.mark.asyncio
async def test_user_edit_skin(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)

    photo_file = BytesIO()
    Image.new(mode="RGB", size=(64, 64), color=(255, 0, 0)).save(photo_file, format="PNG")
    image_b64 = base64.b64encode(photo_file.getvalue()).decode("utf8")

    response = await client.patch("/launcher/v1/users/me", auth=TokenAuth(session.make_token()), json=PatchUserData(
        skin=f"data:image/png;base64,{image_b64}"
    ).model_dump())
    assert response.status_code == 200
    resp = UserInfoResponse(**response.json())
    assert resp.skin is not None
    assert resp.cape is None
