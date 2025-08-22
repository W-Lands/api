from __future__ import annotations

from enum import StrEnum

from tortoise import fields, Model

from wlands import models


class ReportType(StrEnum):
    CHAT = "CHAT"
    SKIN = "SKIN"
    USERNAME = "USERNAME"


class ReportReason(StrEnum):
    I_WANT_TO_REPORT_THEM = "I_WANT_TO_REPORT_THEM"
    HARASSMENT_OR_BULLYING = "HARASSMENT_OR_BULLYING"
    HATE_SPEECH = "HATE_SPEECH"
    ALCOHOL_TOBACCO_DRUGS = "ALCOHOL_TOBACCO_DRUGS"
    SELF_HARM_OR_SUICIDE = "SELF_HARM_OR_SUICIDE"
    CHILD_SEXUAL_EXPLOITATION_OR_ABUSE = "CHILD_SEXUAL_EXPLOITATION_OR_ABUSE"
    TERRORISM_OR_VIOLENT_EXTREMISM = "TERRORISM_OR_VIOLENT_EXTREMISM"
    NON_CONSENSUAL_INTIMATE_IMAGERY = "NON_CONSENSUAL_INTIMATE_IMAGERY"
    SEXUALLY_INAPPROPRIATE = "SEXUALLY_INAPPROPRIATE"


class PlayerReport(Model):
    id: int = fields.BigIntField(pk=True)
    reporter: models.User = fields.ForeignKeyField("models.User", related_name="reporter")
    reported: models.User = fields.ForeignKeyField("models.User", related_name="reported")
    comment: str = fields.TextField(max_length=1024)
    type: ReportType = fields.CharEnumField(ReportType)
    reason: ReportReason | None = fields.CharEnumField(ReportReason, null=True)
    client_name: str = fields.CharField(max_length=32)
    server_address: str = fields.CharField(max_length=128)
