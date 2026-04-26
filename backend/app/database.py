import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

_default_db = os.path.join(os.path.dirname(__file__), "..", "..", "diffscan.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{os.path.abspath(_default_db)}")

_kwargs = {}
if DATABASE_URL.startswith("sqlite"):
    _kwargs["connect_args"] = {"check_same_thread": False}
else:
    _kwargs["pool_pre_ping"] = True

engine = create_engine(DATABASE_URL, **_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
