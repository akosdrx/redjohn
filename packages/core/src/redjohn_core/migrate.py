"""Programmatic Alembic runner — engine startup and tests both migrate through here."""

from __future__ import annotations

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config

_HERE = Path(__file__).resolve()
# repo layout: packages/core/migrations; wheel layout: redjohn_core/migrations
MIGRATIONS_DIR = (
    _HERE.parents[2] / "migrations"
    if (_HERE.parents[2] / "migrations").exists()
    else _HERE.parent / "migrations"
)


def _config(db_path: Path) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
    return cfg


def migrate_sync(db_path: Path) -> None:
    """Upgrade the given SQLite database file to head (creates it if missing)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    command.upgrade(_config(db_path), "head")


async def migrate(db_path: Path) -> None:
    """Async wrapper: Alembic is sync; run it off the event loop."""
    await asyncio.to_thread(migrate_sync, db_path)
