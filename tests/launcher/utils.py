from typing import Generator

from httpx import Auth, Request, Response


class TokenAuth(Auth):
    __slots__ = ("token",)

    def __init__(self, token: str) -> None:
        self._token = token

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        request.headers["Authorization"] = self._token
        yield request
