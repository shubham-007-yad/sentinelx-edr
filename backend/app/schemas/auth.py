from pydantic import BaseModel

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
