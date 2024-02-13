from pydantic import BaseModel


class CreateUser(BaseModel):
    login: str
    email: str
    password: str

    telegram_id: int | None = None
