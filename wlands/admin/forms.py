from pydantic import BaseModel, EmailStr, SecretStr


class LoginForm(BaseModel):
    email: EmailStr
    password: SecretStr


class UserCreateForm(BaseModel):
    nickname: str
    password: SecretStr
