import hmac
from base64 import b32decode, b64decode
from io import BytesIO
from struct import pack, unpack
from time import time

from magic import from_buffer

from wlands.models import User


class Mfa:
    @staticmethod
    def getCode(user: User = None, secret: str = None) -> str | None:
        if user is not None and user.mfa_key is not None:
            key = user.mfa_key.upper()
        elif secret is not None:
            key = secret.upper()
        else:
            return

        key = b32decode(key.upper() + '=' * ((8 - len(key)) % 8))
        counter = pack('>Q', int(time() / 30))
        mac = hmac.new(key, counter, "sha1").digest()
        offset = mac[-1] & 0x0f
        binary = unpack('>L', mac[offset:offset + 4])[0] & 0x7fffffff
        return str(binary)[-6:].zfill(6)


def getImage(image: str) -> BytesIO | None:
    if not isinstance(image, str) \
            or not (image.startswith("data:image/") or image.startswith("data:application/octet-stream")) \
            or "base64" not in image.split(",")[0]:
        return

    image = BytesIO(b64decode(image.split(",")[1].encode("utf8")))
    mime = from_buffer(image.read(1024), mime=True)
    if not mime.startswith("image/"):
        return

    return image
