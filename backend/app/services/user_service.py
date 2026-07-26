from typing import Optional, List
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate
from app.auth.hashing import get_password_hash, verify_password

def get_user_by_id(db: Session, user_id: UUID) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email.lower()).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()

def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
    return db.query(User).offset(skip).limit(limit).all()

def create_user(db: Session, user_in: UserCreate) -> User:
    hashed_pwd = get_password_hash(user_in.password)
    db_user = User(
        email=user_in.email.lower(),
        username=user_in.username,
        password_hash=hashed_pwd,
        role=user_in.role,
        is_active=user_in.is_active if user_in.is_active is not None else True,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username_or_email: str, password: str) -> Optional[User]:
    target = username_or_email.strip()
    if "@" in target:
        user = get_user_by_email(db, target)
    else:
        user = get_user_by_username(db, target)
        
    if not user:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user

def update_user(db: Session, db_user: User, user_in: UserUpdate) -> User:
    update_data = user_in.model_dump(exclude_unset=True)
    if "password" in update_data and update_data["password"]:
        hashed_pwd = get_password_hash(update_data["password"])
        db_user.password_hash = hashed_pwd
        del update_data["password"]
    
    if "email" in update_data and update_data["email"]:
        update_data["email"] = update_data["email"].lower()

    for field, value in update_data.items():
        setattr(db_user, field, value)
        
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def delete_user(db: Session, db_user: User) -> None:
    db.delete(db_user)
    db.commit()

