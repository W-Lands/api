from pydantic import BaseModel, EmailStr, SecretStr


class LoginForm(BaseModel):
    email: EmailStr
    password: SecretStr
