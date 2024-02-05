from pydantic import BaseModel


class JoinRequestData(BaseModel):
    selectedProfile: str | None = None
    serverId: str | None = None

