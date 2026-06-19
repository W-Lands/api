from datetime import datetime
from enum import Enum

from starlette.datastructures import URL
from starlette.requests import Request


def format_size(value: int) -> str:
    if value > 1024 * 1024 * 1024:
        return f"{value / 1024 / 1024 / 1024:.2f} GB"
    elif value > 1024 * 1024:
        return f"{value / 1024 / 1024:.2f} MB"
    elif value > 1024:
        return f"{value / 1024:.2f} KB"
    return f"{value} B"


def format_enum(value: Enum) -> str:
    return value.name.lower().capitalize()


def format_bool(value: bool) -> str:
    return "✓" if value else "×"


def format_datetime(value: datetime, html: bool = False) -> str:
    if html:
        return value.strftime("%Y-%m-%dT%H:%M")
    return value.strftime("%d.%m.%Y %H:%M:%S")


def jinja_append_query_to_url(url: URL, request: Request, *add_params) -> URL:
    return url.include_query_params(**{
        param: request.query_params[param]
        for param in add_params
        if param in request.query_params
    })


def jinja_append_param_to_url(url: URL, param: str, value: str) -> URL:
    return url.include_query_params(**{param: value})
