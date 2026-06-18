import asyncio
import base64
import hmac
import struct
from base64 import b32decode, b64decode
from concurrent.futures.thread import ThreadPoolExecutor
from io import BytesIO
from time import time
from typing import cast, BinaryIO

from PIL import Image
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

        offset_code = cast(str, Mfa.get_code(user, secret, _time_offset=-5))
        return code, offset_code


def get_image_from_b64(image: str) -> BytesIO | None:
    if not isinstance(image, str) \
            or not (image.startswith("data:image/") or image.startswith("data:application/octet-stream")) \
            or "base64" not in image.split(",")[0]:
        return None

    image = BytesIO(b64decode(image.split(",")[1].encode("ascii")))
    mime = from_buffer(image.read(1024), mime=True)
    if not mime.startswith("image/"):
        return None

    return image


image_worker = ThreadPoolExecutor(2, "Image Worker")


def _reencode_png_sync(file: BytesIO) -> BytesIO:
    img = Image.open(file)
    out = BytesIO()
    img.save(out, format="PNG")
    return out


async def reencode_png(file: BytesIO) -> BytesIO:
    return await asyncio.get_running_loop().run_in_executor(image_worker, _reencode_png_sync, file)


def _make_cape_preview_sync(file: BinaryIO) -> str:
    img = Image.open(file)
    out = BytesIO()
    img.crop((0, 0, 12, 17)).save(out, format="PNG")
    return base64.b64encode(out.getvalue()).decode("ascii")


async def make_cape_preview(file: BinaryIO) -> str:
    return await asyncio.get_running_loop().run_in_executor(image_worker, _make_cape_preview_sync, file)
