from uuid import UUID

from Crypto.PublicKey import RSA
from fastapi import FastAPI, Depends, Response

from .dependencies import mc_user_auth, mc_user_auth_data
from .schemas import JoinRequestData
from ..config import YGGDRASIL_PUBLIC_STR
from ..exceptions import BadRequestException, ForbiddenException
from ..models import PlayerKeyPair, GameJoinRequest, User

app = FastAPI()


@app.get("/services/player/attributes")
async def player_attributes():
    return {
        "privileges": {
            "onlineChat": {
                "enabled": True
            },
            "multiplayerServer": {
                "enabled": True
            },
            "multiplayerRealms": {
                "enabled": False
            },
            "telemetry": {
                "enabled": False
            }
        },
        "profanityFilterPreferences": {
            "profanityFilterOn": False
        },
        # "banStatus": {
        #    "bannedScopes": {
        #        "MULTIPLAYER": {
        #            "banId": "579aa9f9-8e6c-4151-bbff-69328c22fdaf",
        #            "scope": "MULTIPLAYER",
        #            "expires": datetime(2200, 1, 1).strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
        #            "reason": "5",
        #            "reasonMessage": "Test"
        #        }
        #    }
        # }
    }


@app.post("/services/player/certificates")
async def player_certificates(user: User = Depends(mc_user_auth)):
    if (keyPair := await PlayerKeyPair.get_or_none(user=user)) is not None and keyPair.can_be_refreshed:
        await keyPair.delete()
        keyPair = None

    if keyPair is None:
        priv = RSA.generate(2048)
        pub = priv.publickey()
        keyPair = await PlayerKeyPair.create(
            user=user, private_key=priv.export_key('PEM', pkcs=8).decode("utf8"),
            public_key=pub.export_key('PEM').decode("utf8"), signature_v2="AA=="
        )
        await keyPair.update(signature_v2=keyPair.generate_signature())

    expMillis = str(keyPair.expires.timestamp()).split(".")[1].ljust(6, "0")
    refMillis = str(keyPair.refreshes.timestamp()).split(".")[1].ljust(6, "0")
    return {
        "keyPair": {
            "privateKey": keyPair.private_key.replace("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY")
            .replace("END PRIVATE KEY", "END RSA PRIVATE KEY"),
            "publicKey": keyPair.public_key.replace("BEGIN PUBLIC KEY", "BEGIN RSA PUBLIC KEY")
            .replace("END PUBLIC KEY", "END RSA PUBLIC KEY"),
        },
        "publicKeySignature": keyPair.signature,
        "publicKeySignatureV2": keyPair.signature_v2,
        "expiresAt": keyPair.expires.strftime("%Y-%m-%dT%H:%M:%S.") + expMillis + "Z",
        "refreshedAfter": keyPair.refreshes.strftime("%Y-%m-%dT%H:%M:%S.") + refMillis + "Z",
    }


@app.get("/services/privacy/blocklist")
async def blocklist():
    return {
        "blockedProfiles": []
    }


@app.get("/services/player/report", status_code=501)
async def player_report():
    return {}


@app.post("/session/session/minecraft/join")
async def mc_join(data: JoinRequestData, user: User = Depends(mc_user_auth_data)):
    if not data.selectedProfile or not data.serverId:
        raise BadRequestException("One or more required fields was missing.")
    if UUID(data.selectedProfile) != user.id:
        raise ForbiddenException("Invalid token.")

    await GameJoinRequest.create(user=user, server_id=data.serverId)
    return Response()


@app.get("/session/session/minecraft/hasJoined")
async def mc_has_joined(serverId: str | None, username: str | None):
    if not serverId or not username:
        raise BadRequestException("One or more required fields was missing.")

    join_request = await GameJoinRequest.get_or_none(server_id=serverId, user__nickname=username).select_related("user")
    if join_request is None:
        raise ForbiddenException("Player not joined.", 401)

    await join_request.delete()
    return {
        "id": str(join_request.user.id),
        "name": str(join_request.user.nickname),
        "properties": join_request.user.properties(True)
    }


@app.get("/session/session/minecraft/profile/{user_id}")
async def mc_profile(user_id: UUID, unsigned: bool = False):
    if (user := await User.get_or_none(id=user_id)) is None:
        raise BadRequestException("Profile does not exist.")

    return {
        "id": user.id.hex.replace("-", ""),
        "name": user.nickname,
        "properties": user.properties(not unsigned)
    }


@app.get("/services/publickeys")
async def yggdrasil_keys():
    return {
        "profilePropertyKeys": [{"publicKey": YGGDRASIL_PUBLIC_STR}],
        "playerCertificateKeys": [{"publicKey": YGGDRASIL_PUBLIC_STR}],
    }
