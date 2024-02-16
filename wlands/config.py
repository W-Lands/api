from base64 import b64encode
from os import environ, urandom
from os.path import exists

from Crypto.PublicKey import RSA
from s3lite import Client

if not exists("keys/private.pem"):
    raise RuntimeError("Please create 2048 bit rsa keypair in \"keys\" directory. " +
                       "Keys must be named \"private.pem\" and \"public.pem\"")

S3 = Client(environ["S3_ACCESS_KEY_ID"], environ["S3_SECRET_ACCESS_KEY"], environ["S3_ENDPOINT"])
DATABASE_URL = environ["DATABASE_URL"]
MIGRATIONS_DIR = environ.get("MIGRATIONS_DIR", "./migrations")

with open("keys/private.pem", "r") as privkey:
    YGGDRASIL_PRIVATE_STR = privkey.read()
    YGGDRASIL_PRIVATE_KEY = RSA.import_key(YGGDRASIL_PRIVATE_STR)
    YGGDRASIL_PRIVATE_STR = "".join(YGGDRASIL_PRIVATE_STR.split("\n")[1:-2])

with open("keys/public.pem", "r") as pubkey:
    YGGDRASIL_PUBLIC_STR = pubkey.read()
    YGGDRASIL_PUBLIC_KEY = RSA.import_key(YGGDRASIL_PUBLIC_STR)
    YGGDRASIL_PUBLIC_STR = "".join(YGGDRASIL_PUBLIC_STR.split("\n")[1:-2])

INTERNAL_AUTH_TOKEN = environ.get("INTERNAL_AUTH_TOKEN", b64encode(urandom(64)).decode("utf8"))
