from typing import List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_admin
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate, UserOut
from app.services import user_service

router = APIRouter(prefix="/users", tags=["User Management"])

@router.post(
    "",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user (Admin Only)",
    description="Allows an Administrator to create a new user account with assigned role (ADMIN, ANALYST, VIEWER)."
)
def create_user(
    user_in: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
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

@router.get(
    "",
    response_model=List[UserOut],
    summary="List all users (Admin Only)",
    description="Retrieves a list of all registered users."
)
def list_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    return user_service.get_users(db, skip=skip, limit=limit)

@router.get(
    "/{user_id}",
    response_model=UserOut,
    summary="Get user details by ID (Admin Only)"
)
def get_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    user = user_service.get_user_by_id(db, user_id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    return user

@router.patch(
    "/{user_id}",
    response_model=UserOut,
    summary="Update user role, status, or details (Admin Only)"
)
def update_user(
    user_id: UUID,
    user_in: UserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    db_user = user_service.get_user_by_id(db, user_id=user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    # Check email uniqueness if email is changed
    if user_in.email and user_in.email.lower() != db_user.email.lower():
        existing_email = user_service.get_user_by_email(db, email=user_in.email)
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with this email already exists."
            )
            
    # Check username uniqueness if username is changed
    if user_in.username and user_in.username != db_user.username:
        existing_username = user_service.get_user_by_username(db, username=user_in.username)
        if existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A user with this username already exists."
            )

    return user_service.update_user(db, db_user=db_user, user_in=user_in)

@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user account (Admin Only)"
)
def delete_user(
    user_id: UUID,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    if admin.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot delete their own account."
        )
    db_user = user_service.get_user_by_id(db, user_id=user_id)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    user_service.delete_user(db, db_user=db_user)
    return None
