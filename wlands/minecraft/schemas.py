from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from wlands.models import ReportType, ReportReason


class JoinRequestData(BaseModel):
    selectedProfile: str | None = None
    serverId: str | None = None


class ReportedMessage(BaseModel):
    index: int
    profile_id: UUID = Field(alias="profileId")
    session_id: UUID = Field(alias="sessionId")
    timestamp: datetime
    salt: int
    last_seen: list[str] = Field(alias="lastSeen")
    message: str
    signature: str
    reported: bool = Field(alias="messageReported")


class ReportEvidence(BaseModel):
    messages: list[ReportedMessage]


class ReportEntity(BaseModel):
    profile_id: UUID = Field(alias="profileId")


class ReportBody(BaseModel):
    comment: str = Field(alias="opinionComments")
    reason: ReportReason | None = None
    evidence: ReportEvidence | None = None
    entity: ReportEntity = Field(alias="reportedEntity")
    created_at: datetime = Field(alias="createdTime")


class ReportClientInfo(BaseModel):
    version: str = Field(alias="clientVersion")
    locale: str


class ReportServerInfo(BaseModel):
    address: str


class ReportRequest(BaseModel):
    version: Literal[1]
    id: UUID
    report: ReportBody
    client_info: ReportClientInfo = Field(alias="clientInfo")
    server_info: ReportServerInfo = Field(alias="thirdPartyServerInfo")
    type: ReportType = Field(alias="reportType")
