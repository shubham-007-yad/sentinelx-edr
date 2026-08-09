import pytest
import uuid
from app.db.database import Base, engine
from app.db.session import SessionLocal
from app.models.security_policy import SecurityPolicy, PolicyCategory
from app.schemas.security_policy import SecurityPolicyCreate, SecurityPolicyOut, SecurityPolicyUpdate


def test_security_policy_db_lifecycle():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # 1. Create Security Policy
        policy = SecurityPolicy(
            policy_name="USB Block Executables",
            category=PolicyCategory.USB,
            version=1,
            enabled=True,
            priority=100,
            configuration={"block_executables": True, "read_only": False, "allowed_vids": ["0781"]},
            created_by="SecAdmin"
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)

        # Assertions
        assert policy.id is not None
        assert isinstance(policy.id, uuid.UUID)
        assert policy.policy_name == "USB Block Executables"
        assert policy.category == PolicyCategory.USB
        assert policy.version == 1
        assert policy.enabled is True
        assert policy.priority == 100
        assert policy.configuration == {"block_executables": True, "read_only": False, "allowed_vids": ["0781"]}
        assert policy.created_by == "SecAdmin"
        assert policy.created_at is not None
        assert policy.updated_at is not None
        assert "<SecurityPolicy id=" in repr(policy)

        # 2. Update Policy
        policy.version = 2
        updated_config = dict(policy.configuration)
        updated_config["read_only"] = True
        policy.configuration = updated_config
        db.commit()
        db.refresh(policy)


        assert policy.version == 2
        assert policy.configuration["read_only"] is True

        # 3. Test Pydantic Schema
        schema_out = SecurityPolicyOut.model_validate(policy)
        assert schema_out.id == policy.id
        assert schema_out.category == PolicyCategory.USB
        assert schema_out.policy_name == "USB Block Executables"

    finally:
        db.close()
