import hmac
import struct
from base64 import b32decode, b64decode
from io import BytesIO
from time import time

from magic import from_buffer

from wlands.models import User


class Mfa:
    @staticmethod
    def get_code(user: User = None, secret: str = None, *, _time_offset: int = 0) -> str | None:
        if user is not None and user.mfa_key is not None:
            key = user.mfa_key.upper()
        elif secret is not None:
            key = secret.upper()
        else:
            return None

        key = b32decode(key.upper() + "=" * ((-len(key)) % 8))
        counter = struct.pack(">Q", int((time() + _time_offset) / 30))
        mac = hmac.new(key, counter, "sha1").digest()
        offset = mac[-1] & 0x0f
        binary = struct.unpack(">L", mac[offset:offset + 4])[0] & 0x7fffffff
        return str(binary)[-6:].zfill(6)

    @staticmethod
    def get_codes(user: User = None, secret: str = None) -> tuple[str, str] | None:
        code = Mfa.get_code(user, secret)
        if code is None:
            return None

        now = int(time() / 30)
        last = int((time() - 5) / 30)
        if now == last:
            return code, code

        return code, Mfa.get_code(user, secret, _time_offset=-5)


def get_image_from_b64(image: str) -> BytesIO | None:
    if not isinstance(image, str) \
            or not (image.startswith("data:image/") or image.startswith("data:application/octet-stream")) \
            or "base64" not in image.split(",")[0]:
        return None

    image = BytesIO(b64decode(image.split(",")[1].encode("utf8")))
    mime = from_buffer(image.read(1024), mime=True)
    if not mime.startswith("image/"):
        return None

    return image
