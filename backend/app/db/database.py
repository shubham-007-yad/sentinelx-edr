from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings

# Enterprise production connection pooling settings
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,       # Verifies connection health before giving to pool
    pool_size=20,             # Base number of pooled connections
    max_overflow=30,          # Maximum overflow connections during traffic bursts
    pool_timeout=30,          # Seconds to wait before timing out on pool acquisition
    pool_recycle=1800,        # Recycles connections older than 30 minutes
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
