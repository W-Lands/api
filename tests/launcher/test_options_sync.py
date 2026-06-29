import pytest
from httpx import AsyncClient

from tests.launcher.data import TEST_EMAIL, TEST_NICKNAME, TEST_PASSWORD_HASH
from tests.launcher.utils import TokenAuth
from wlands.config import OPTIONS_SYNC_SLOTS_PER_USER
from wlands.launcher.v1.response_models import OptionsSyncInfo
from wlands.models import User, GameSession, OptionsTxt


@pytest.mark.asyncio
async def test_get_sync_slots_empty(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)
    auth = TokenAuth(session.make_token())

    response = await client.get("/launcher/v1/game-options", auth=auth)
    assert response.status_code == 200
    resp = OptionsSyncInfo(**response.json())
    assert resp.slots == []
    assert resp.slots_left == OPTIONS_SYNC_SLOTS_PER_USER


@pytest.mark.asyncio
async def test_push_and_get_settings(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)
    auth = TokenAuth(session.make_token())

    response = await client.post("/launcher/v1/game-options", auth=auth, json={"name": "test-slot"})
    assert response.status_code == 204

    response = await client.post("/launcher/v1/game-options/test-slot", auth=auth, json=OptionsTxt(
        autoJump=True,
        autoSuggestions="asdqwe",
    ).model_dump(exclude_none=True))
    assert response.status_code == 204

    response = await client.get("/launcher/v1/game-options", auth=auth)
    assert response.status_code == 200
    resp = OptionsSyncInfo(**response.json())
    assert len(resp.slots) == 1
    assert resp.slots[0].name == "test-slot"
    assert resp.slots_left == OPTIONS_SYNC_SLOTS_PER_USER - 1

    response = await client.get("/launcher/v1/game-options/test-slot", auth=auth)
    assert response.status_code == 200
    assert response.json() == {"autoJump": True}


@pytest.mark.asyncio
async def test_get_settings_unknown_slot(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)
    auth = TokenAuth(session.make_token())

    response = await client.get("/launcher/v1/game-options/test-slot", auth=auth)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_push_settings_limit_exceeded(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)
    auth = TokenAuth(session.make_token())

    for i in range(OPTIONS_SYNC_SLOTS_PER_USER):
        response = await client.post("/launcher/v1/game-options", auth=auth, json={"name": f"test-slot-{i}"})
        assert response.status_code == 204

    response = await client.post(f"/launcher/v1/game-options", auth=auth, json={"name": "test-slot-limit"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_merge_settings(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)
    auth = TokenAuth(session.make_token())

    response = await client.post("/launcher/v1/game-options", auth=auth, json={"name": "test-slot"})
    assert response.status_code == 204

    response = await client.post("/launcher/v1/game-options/test-slot", auth=auth, json=OptionsTxt(
        autoJump=True,
        autoSuggestions="asdqwe",
        mainHand="left",
    ).model_dump(exclude_none=True))
    assert response.status_code == 204

    response = await client.post("/launcher/v1/game-options/test-slot", auth=auth, json=OptionsTxt(
        soundCategory_master=0.5,
        soundCategory_music=0.75,
        mainHand="\"right\"",
    ).model_dump(exclude_none=True))
    assert response.status_code == 204

    response = await client.get("/launcher/v1/game-options/test-slot", auth=auth)
    assert response.status_code == 200
    assert response.json() == {
        "autoJump": True,
        "mainHand": "\"right\"",
        "soundCategory_master": 0.5,
        "soundCategory_music": 0.75,
    }


@pytest.mark.asyncio
async def test_options_sync_keybinds(client: AsyncClient) -> None:
    user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
    session = await GameSession.create(user=user)
    auth = TokenAuth(session.make_token())

    response = await client.post("/launcher/v1/game-options", auth=auth, json={"name": "test-slot"})
    assert response.status_code == 204

    response = await client.post("/launcher/v1/game-options/test-slot", auth=auth, json={
        "key_key.attack": "key.mouse.left",
        "key_key.use": -99,
    })
    assert response.status_code == 204

    response = await client.get("/launcher/v1/game-options/test-slot", auth=auth)
    assert response.status_code == 200
    assert response.json() == {
        "key_key.attack": "key.mouse.left",
        "key_key.use": "key.mouse.right",
    }

    response = await client.get("/launcher/v1/game-options/test-slot", auth=auth, params={"old_format": False})
    assert response.status_code == 200
    assert response.json() == {
        "key_key.attack": "key.mouse.left",
        "key_key.use": "key.mouse.right",
    }

    response = await client.get("/launcher/v1/game-options/test-slot", auth=auth, params={"old_format": True})
    assert response.status_code == 200
    assert response.json() == {
        "key_key.attack": -100,
        "key_key.use": -99,
    }
