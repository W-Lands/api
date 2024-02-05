class CustomBodyException(Exception):
    def __init__(self, code: int, body: dict):
        self.code = code
        self.body = body


class BadRequestException(CustomBodyException):
    def __init__(self, message: str):
        super().__init__(400, {
            "errorType": "BAD_REQUEST", "error": "Bad Request", "errorMessage": message, "developerMessage": message
        })


class ForbiddenException(CustomBodyException):
    def __init__(self, message: str, code: int = 403):
        super().__init__(code, {
            "errorType": "FORBIDDEN", "error": "ForbiddenOperationException",
            "errorMessage": message, "developerMessage": message
        })
