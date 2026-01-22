import pytest
from httpx import AsyncClient
from pydantic import BaseModel

from tests.launcher.data import TEST_PASSWORD_HASH, TEST_NICKNAME, TEST_EMAIL, TEST_EMAIL2, TEST_NICKNAME2
from tests.launcher.utils import TokenAuth
from wlands.launcher.v1.response_models import ProfileInfo
from wlands.models import GameProfile, User, GameSession

DUMMY_MANIFEST = {
    "arguments": {
        "game": [
            "--username",
            "${auth_player_name}",
            "--version",
            "${version_name}",
        ],
        "jvm": [
            {
                "rules": [
                    {
                        "action": "allow",
                        "os": {
                            "arch": "x86"
                        }
                    }
                ],
                "value": "-some-arg"
            },
            "-Danother-arg",
        ]
    },
    "assetIndex": {
        "id": "26",
        "sha1": "2c3980f6ea388330c7851205646d38a29d64c86e",
        "size": 1234,
        "totalSize": 123456789,
        "url": "https://unreachable.local/v1/packages/2c3980f6ea388330c7851205646d38a29d64c86e/26.json"
    },
    "assets": "26",
    "complianceLevel": 1,
    "downloads": {
        "client": {
            "sha1": "a19d9badbea944a4369fd0059e53bf7286597576",
            "size": 29525242,
            "url": "https://unreachable.local/v1/objects/a19d9badbea944a4369fd0059e53bf7286597576/client.jar"
        },
        "client_mappings": {
            "sha1": "bdeb624c3aefba11d9d40f34bc96176350b549b6",
            "size": 10989738,
            "url": "https://unreachable.local/v1/objects/bdeb624c3aefba11d9d40f34bc96176350b549b6/client.txt"
        },
        "server": {
            "sha1": "6bce4ef400e4efaa63a13d5e6f6b500be969ef81",
            "size": 57555044,
            "url": "https://unreachable.local/v1/objects/6bce4ef400e4efaa63a13d5e6f6b500be969ef81/server.jar"
        },
        "server_mappings": {
            "sha1": "eb1e1eb47cb740012fc82eacc394859463684132",
            "size": 8186232,
            "url": "https://unreachable.local/v1/objects/eb1e1eb47cb740012fc82eacc394859463684132/server.txt"
        }
    },
    "id": "1.21.10",
    "javaVersion": {
        "component": "java-runtime-delta",
        "majorVersion": 21
    },
    "libraries": [
        {
            "downloads": {
                "artifact": {
                    "path": "a/b/c/e/1.2.3/e-1.2.3.jar",
                    "sha1": "0172931663a09a1fa515567af5fbef00897d3c04",
                    "size": 54321,
                    "url": "https://unreachable.local/a/b/c/e/1.2.3/e-1.2.3.jar"
                }
            },
            "name": "a.b.c:e:1.2.3",
            "rules": [
                {
                    "action": "allow",
                    "os": {
                        "name": "windows"
                    }
                }
            ]
        },
        {
            "downloads": {
                "artifact": {
                    "path": "a/b/c/d/1.2.3/d-1.2.3.jar",
                    "sha1": "0172931663a09a1fa515567af5fbef00897d3c04",
                    "size": 12345,
                    "url": "https://unreachable.local/a/b/c/d/1.2.3/d-1.2.3.jar"
                }
            },
            "name": "a.b.c:d:1.2.3"
        }
    ],
    "mainClass": "asd.qwe.testing.Main",
    "minimumLauncherVersion": 21,
    "releaseTime": "2025-07-17T12:04:02+00:00",
    "time": "2025-07-17T12:04:02+00:00",
    "type": "release"
}


class ProfilesList(BaseModel):
    profiles: list[ProfileInfo]


@pytest.mark.asyncio
async def test_get_profiles_empty(client: AsyncClient) -> None:
    response = await client.get("/launcher/v1/profiles")
    assert response.status_code == 200
    resp = response.json()
    assert len(resp) == 0


@pytest.mark.asyncio
async def test_get_profiles_multiple(client: AsyncClient) -> None:
    profile1 = await GameProfile.create(name="prof1", description="idk", version_manifest=DUMMY_MANIFEST, public=True)
    profile2 = await GameProfile.create(name="prof2", description="idk", version_manifest=DUMMY_MANIFEST, public=True)
    profile3 = await GameProfile.create(name="prof3", description="idk", version_manifest=DUMMY_MANIFEST, public=True)

    response = await client.get("/launcher/v1/profiles")
    assert response.status_code == 200
    resp = ProfilesList(profiles=response.json())
    assert len(resp.profiles) == 3
    assert resp.profiles[0].id == profile3.id
    assert resp.profiles[1].id == profile2.id
    assert resp.profiles[2].id == profile1.id


@pytest.mark.parametrize(
    ("params", "as_user", "profile_idxs",),
    [
        (None, None, [2, 0],),
        ({"only_public": "false"}, None, [2, 0],),
        ({"only_public": "false"}, "user", [2, 0],),
        ({"only_public": "false"}, "admin", [2, 1, 0],),
    ],
    ids=(
        "no params",
        "only_public=false",
        "only_public=false as user",
        "only_public=false as admin",
    ),
)
@pytest.mark.asyncio
async def test_get_profiles_multiple_public_private(
        client: AsyncClient, params: dict | None, as_user: str | None, profile_idxs: list[int],
) -> None:
    if as_user is not None:
        user = await User.create(email=TEST_EMAIL, nickname=TEST_NICKNAME, password=TEST_PASSWORD_HASH)
        admin = await User.create(email=TEST_EMAIL2, nickname=TEST_NICKNAME2, password=TEST_PASSWORD_HASH, admin=True)
        user_session = await GameSession.create(user=user)
        admin_session = await GameSession.create(user=admin)
        tokens = {"user": user_session.make_token(), "admin": admin_session.make_token()}
        auth = TokenAuth(tokens[as_user])
    else:
        auth = None

    profile1 = await GameProfile.create(name="prof1", description="idk", version_manifest=DUMMY_MANIFEST, public=True)
    profile2 = await GameProfile.create(name="prof2", description="idk", version_manifest=DUMMY_MANIFEST, public=False)
    profile3 = await GameProfile.create(name="prof3", description="idk", version_manifest=DUMMY_MANIFEST, public=True)
    profile_ids = [profile1.id, profile2.id, profile3.id]

    expect_profile_ids = [profile_ids[idx] for idx in profile_idxs]

    response = await client.get("/launcher/v1/profiles", params=params, auth=auth)
    assert response.status_code == 200
    resp = ProfilesList(profiles=response.json())
    assert len(resp.profiles) == len(expect_profile_ids)
    actual_profile_ids = [prof.id for prof in resp.profiles]
    assert actual_profile_ids == expect_profile_ids
