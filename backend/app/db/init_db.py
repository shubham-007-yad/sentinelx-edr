from sqlalchemy.orm import Session
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserUpdate
from app.services import user_service

def init_db(db: Session) -> None:
    """
    Seed initial database data, ensuring at least one Admin account exists with known credentials.
    """
    admin_user = user_service.get_user_by_username(db, username="admin")
    if not admin_user:
        admin_in = UserCreate(
            email="admin@sentinelx.io",
            username="admin",
            password="AdminPassword123!",
            role=UserRole.ADMIN,
            is_active=True
        )
        user_service.create_user(db, user_in=admin_in)
    else:
        user_service.update_user(
            db,
            db_user=admin_user,
            user_in=UserUpdate(
                password="AdminPassword123!",
                role=UserRole.ADMIN,
                is_active=True
            )
        )
