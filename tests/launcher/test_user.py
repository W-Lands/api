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


@pytest.mark.parametrize(
    ("skin_color", "skin_dims", "skin_is_none", "expect_code"),
    [
        ((255, 0, 0), (64, 64), False, 200),
        ((255, 0, 0), (65, 64), False, 400),
        ((255, 0, 0), (64, 65), False, 400),
        ((255, 0, 0), (65, 65), False, 400),
        (None, None, True, 200),
    ],
    ids=(
            "solid red image 64x64",
            "invalid skin 65x64",
            "invalid skin 64x65",
            "invalid skin 65x65",
            "no skin",
    ),
)
@pytest.mark.usefixtures("fake_s3_server")
@pytest.mark.asyncio
async def test_user_edit_skin(
        client: AsyncClient, skin_color: tuple[int, int, int] | None, skin_dims: tuple[int, int] | None,
        skin_is_none: bool, expect_code: int,
) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)

    if skin_color is not None and skin_dims is not None:
        photo_file = BytesIO()
        Image.new(mode="RGB", size=skin_dims, color=skin_color).save(photo_file, format="PNG")
        image_b64 = base64.b64encode(photo_file.getvalue()).decode("utf8")
        skin_data = f"data:image/png;base64,{image_b64}"
    else:
        skin_data = None

    response = await client.patch("/launcher/v1/users/me", auth=TokenAuth(session.make_token()), json={
        "skin": skin_data,
    })
    assert response.status_code == expect_code
    if expect_code == 200:
        resp = UserInfoResponse(**response.json())
        assert (resp.skin is None) == skin_is_none
        assert resp.cape is None

    response = await client.patch("/launcher/v1/users/me", auth=TokenAuth(session.make_token()), json=PatchUserData(
        skin="",
    ).model_dump())
    assert response.status_code == 200
    resp = UserInfoResponse(**response.json())
    assert resp.skin is None
