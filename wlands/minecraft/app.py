from base64 import b64decode
from datetime import datetime, timezone, timedelta
from uuid import UUID

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from fastapi import FastAPI, Depends, Response

from .dependencies import mc_user_auth, mc_user_auth_data
from .schemas import JoinRequestData, ReportRequest
from ..config import YGGDRASIL_PUBLIC_STR
from ..exceptions import BadRequestException, ForbiddenException
from ..models import PlayerKeyPair, GameJoinRequest, User, ReportMessage, ReportType, PlayerReport

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
    if (keypair := await PlayerKeyPair.get_or_none(user=user)) is not None and keypair.can_be_refreshed:
        await keypair.delete()
        keypair = None

    if keypair is None:
        priv = RSA.generate(2048)
        pub = priv.publickey()

        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        sig_v1, sig_v2 = PlayerKeyPair.generate_signatures(user, int(expires_at.timestamp() * 1000), pub)

        keypair = await PlayerKeyPair.create(
            user=user, private_key=priv.export_key("PEM", pkcs=8).decode("utf8"),
            public_key=pub.export_key("PEM").decode("utf8"), signature=sig_v1, signature_v2=sig_v2, expires=expires_at,
        )

    expMillis = str(keypair.expires.timestamp()).split(".")[1].ljust(6, "0")
    refMillis = str(keypair.refreshes.timestamp()).split(".")[1].ljust(6, "0")
    return {
        "keyPair": {
            "privateKey": keypair.private_key.replace(" PRIVATE KEY", " RSA PRIVATE KEY"),
            "publicKey": keypair.public_key.replace(" PUBLIC KEY", " RSA PUBLIC KEY"),
        },
        "publicKeySignature": keypair.signature,
        "publicKeySignatureV2": keypair.signature_v2,
        "expiresAt": keypair.expires.strftime(f"%Y-%m-%dT%H:%M:%S.{expMillis}Z"),
        "refreshedAfter": keypair.refreshes.strftime(f"%Y-%m-%dT%H:%M:%S.{refMillis}Z"),
    }


@app.get("/services/privacy/blocklist")
async def blocklist():
    return {
        "blockedProfiles": []
    }


def itob(value: int) -> bytes:
    return value.to_bytes(4, "big", signed=True)


def ltob(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=True)


@app.post("/services/player/report", status_code=204)
async def player_report_post(data: ReportRequest, user: User = Depends(mc_user_auth)):
    reported_user = await User.get_or_none(id=data.report.entity.profile_id)
    if reported_user is None:
        raise BadRequestException("Unknown user.")

    if data.report.reason is None and data.type is not ReportType.USERNAME:
        raise BadRequestException("Invalid request: expected reason to be in request body.")

    messages = []
    report = PlayerReport(
        reporter=user,
        reported=reported_user,
        comment=data.report.comment,
        type=data.type,
        reason=data.report.reason,
        client_name=data.client_info.version,
        server_address=data.server_info.address,
    )

    if data.type == ReportType.CHAT:
        if data.report.evidence is None or not data.report.evidence.messages:
            raise BadRequestException("Invalid request: expected messages to be in request body.")

        user_ids = list({message.profile_id for message in data.report.evidence.messages})
        users = await User.filter(id__in=user_ids)

        if len(user_ids) != len(users):
            raise BadRequestException("Invalid request: failed to find some of the users.")

        users_dict = {user.id: user for user in users}

        pubkeys = {}
        for keypair in await PlayerKeyPair.filter(user__id__in=user_ids):
            pubkeys[keypair.user_id] = RSA.import_key(keypair.public_key)

        indexes: dict[str, int] = {}

        for idx, message in enumerate(data.report.evidence.messages):
            key = f"{message.profile_id}-{message.session_id}"
            if key in indexes and (indexes[key] + 1) != message.index:
                raise BadRequestException(
                    f"Invalid request: in message {idx}: expected index {indexes[key] + 1}, got {message.index}."
                )
            indexes[key] = message.index

            content = message.message.encode("utf8")

            digest = SHA256.new(itob(1))
            digest.update(message.profile_id.bytes)
            digest.update(message.session_id.bytes)
            digest.update(itob(message.index))
            digest.update(ltob(message.salt))
            digest.update(ltob(int(message.timestamp.timestamp())))
            digest.update(itob(len(content)))
            digest.update(content)
            digest.update(itob(len(message.last_seen)))
            for last_seen in message.last_seen:
                digest.update(b64decode(last_seen))

            valid = PKCS1_v1_5.new(pubkeys[message.profile_id]).verify(digest, b64decode(message.signature))
            if not valid:
                raise BadRequestException(f"Invalid signature for message {idx}.")

            messages.append(ReportMessage(
                report=None,
                user=users_dict[message.profile_id],
                date=message.timestamp,
                text=message.message,
                reported=message.reported,
            ))

    await report.save()
    if messages:
        for message in messages:
            message.report = report
        await ReportMessage.bulk_create(messages)


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
