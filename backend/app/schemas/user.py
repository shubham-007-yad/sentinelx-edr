from uuid import UUID
from datetime import datetime
from typing import Optional, Union
import re
from pydantic import BaseModel, EmailStr, ConfigDict, field_validator
from app.models.user import UserRole

class UserBase(BaseModel):
    email: EmailStr
    username: str
    role: Optional[UserRole] = UserRole.ANALYST
    is_active: Optional[bool] = True

    @field_validator("role", mode="before")
    @classmethod
    def normalize_role(cls, v: Union[str, UserRole, None]) -> Optional[UserRole]:
        if isinstance(v, str):
            v_upper = v.strip().upper()
            for r in UserRole:
                if r.value == v_upper or r.name == v_upper:
                    return r
            raise ValueError(f"Invalid role: '{v}'. Must be one of: {[r.value for r in UserRole]}")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v_stripped = v.strip()
        if len(v_stripped) < 3 or len(v_stripped) > 50:
            raise ValueError("Username must be between 3 and 50 characters long.")
        if not re.match(r"^[a-zA-Z0-9_-]+$", v_stripped):
            raise ValueError("Username can only contain alphanumeric characters, underscores, and hyphens.")
        return v_stripped

class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"[0-9!@#$%^&*()_+\-=\[\]{};':\",./<>?]", v):
            raise ValueError("Password must contain at least one digit or special character.")
        return v

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = None
    password: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

    @field_validator("role", mode="before")
    @classmethod
    def normalize_optional_role(cls, v: Union[str, UserRole, None]) -> Optional[UserRole]:
        if v is not None:
            return UserBase.normalize_role(v)
        return v

    @field_validator("password")
    @classmethod
    def validate_optional_password(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return UserCreate.validate_password_strength(v)
        return v

class UserOut(UserBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
