from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user
from app.auth.jwt import create_access_token
from app.core.config import settings
from app.models.user import User
from app.schemas.auth import LoginRequest
from app.schemas.token import Token
from app.schemas.user import UserCreate, UserOut
from app.services import user_service

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post(
    "/register",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Validates user details, hashes password with Bcrypt, and stores the user in PostgreSQL with assigned role."
)
def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    """
    1. Validate input (email, username format, password strength)
    2. Check duplicate email or username
    3. Hash password using Bcrypt
    4. Store in PostgreSQL database
    5. Return created User response (without password hash)
    """
    db_user_email = user_service.get_user_by_email(db, email=user_in.email)
    if db_user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists."
        )
    db_user_username = user_service.get_user_by_username(db, username=user_in.username)
    if db_user_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this username already exists."
        )
    return user_service.create_user(db, user_in=user_in)

@router.post(
    "/login",
    response_model=Token,
    summary="User Login (OAuth2 Form & Swagger)",
    description="OAuth2 password form login endpoint for authenticating users and issuing JWT access tokens."
)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Authenticate user using Form Data (username/email & password), verify Bcrypt hash, and issue JWT token.
    """
    user = user_service.authenticate_user(
        db, username_or_email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token_str = create_access_token(
        subject=user.username,
        role=user.role.value if hasattr(user.role, "value") else str(user.role),
        expires_delta=access_token_expires
    )
    return {
        "access_token": token_str,
        "token_type": "bearer",
        "user": UserOut.model_validate(user)
    }

@router.post(
    "/login/json",
    response_model=Token,
    summary="User Login (JSON Payload)",
    description="JSON login endpoint for single-page web applications (React SPA)."
)
def login_json(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user using JSON payload (username_or_email & password), verify Bcrypt hash, and issue JWT token.
    """
    user = user_service.authenticate_user(
        db, username_or_email=login_data.username_or_email, password=login_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token_str = create_access_token(
        subject=user.username,
        role=user.role.value if hasattr(user.role, "value") else str(user.role),
        expires_delta=access_token_expires
    )
    return {
        "access_token": token_str,
        "token_type": "bearer",
        "user": UserOut.model_validate(user)
    }

@router.get(
    "/me",
    response_model=UserOut,
    summary="Get current user profile",
    description="Protected endpoint requiring Authorization: Bearer <token>. Returns current authenticated user profile."
)
def read_users_me(current_user: User = Depends(get_current_active_user)):
    """
    Return currently authenticated user profile.
    """
    return current_user
