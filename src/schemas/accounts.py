from database import accounts_validators
from pydantic import BaseModel, EmailStr, field_validator


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str
    message: str = "Please check your email to activate your account."


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"
