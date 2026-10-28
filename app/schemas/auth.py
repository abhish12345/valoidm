from pydantic import BaseModel, EmailStr, field_validator, model_validator
from pydantic import ConfigDict
from typing import Any


class RegisterRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    realm_id: str = "master"
    username: str
    email: str          # plain str — we validate format ourselves, skip deliverability check
    password: str
    first_name: str | None = None
    last_name: str | None = None
    is_admin: bool = False

    @field_validator("username")
    @classmethod
    def username_clean(cls, v: str) -> str:
        v = v.strip().lower()
        if len(v) < 3:
            raise ValueError("username must be at least 3 characters")
        return v

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str
    realm_id: str = "master"
    totp_code: str | None = None   # provide if MFA is enabled


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int         # seconds
    realm_id: str
    username: str
    is_admin: bool
    mfa_required: bool = False


class MFASetupResponse(BaseModel):
    totp_uri: str           # otpauth:// URI for QR code
    secret: str             # raw secret (show once, user stores in authenticator)


class MFAVerifyRequest(BaseModel):
    totp_code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("new password must be at least 8 characters")
        return v


class MeResponse(BaseModel):
    id: str
    realm_id: str
    username: str
    email: str
    display_name: str
    identity_type: str
    status: str
    is_admin: bool
    mfa_enabled: bool
    created_at: Any
