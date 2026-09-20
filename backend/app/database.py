"""Motor y sesiones de base de datos (SQLModel sobre SQLAlchemy)."""
from sqlmodel import SQLModel, Session, create_engine
from sqlalchemy.pool import StaticPool
from . import config

_connect_args = {}
_kwargs = {}
if config.DATABASE_URL.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}
    if ":memory:" in config.DATABASE_URL:
        _kwargs["poolclass"] = StaticPool

engine = create_engine(config.DATABASE_URL, connect_args=_connect_args, **_kwargs)


def init_db() -> None:
    """Crea las tablas si no existen."""
    from . import models  # noqa: F401  (registra los modelos)
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
