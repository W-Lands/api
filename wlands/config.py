from os import environ
from os.path import exists

from Crypto.PublicKey import RSA
from s3lite import Client

if not exists("keys/private.pem"):
    raise RuntimeError("Please create 2048 bit rsa keypair in \"keys\" directory. " +
                       "Keys must be named \"private.pem\" and \"public.pem\"")

S3 = Client(environ["S3_ACCESS_KEY_ID"], environ["S3_SECRET_ACCESS_KEY"], environ["S3_ENDPOINT"])
DATABASE_URL = environ["DATABASE_URL"]

with open("keys/private.pem", "r") as privkey:
    YGGDRASIL_PRIVATE_KEY = RSA.import_key(privkey.read())
