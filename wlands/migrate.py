from asyncio import new_event_loop
from pathlib import Path

from aerich import Command
from tortoise import Tortoise

from .config import DATABASE_URL, MIGRATIONS_DIR


async def migrate():
    command = Command({
        "connections": {"default": DATABASE_URL},
        "apps": {"models": {"models": ["wlands.models", "aerich.models"], "default_connection": "default"}},
    }, location=MIGRATIONS_DIR)
    await command.init()
    if Path(MIGRATIONS_DIR).exists():
        await command.migrate()
        await command.upgrade(True)
    else:
        await command.init_db(True)
    await Tortoise.close_connections()


if __name__ == "__main__":
    new_event_loop().run_until_complete(migrate())