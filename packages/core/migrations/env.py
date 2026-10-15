"""Alembic environment for redjohn-core migrations.

Runs offline (``--sql``) and online against the per-profile SQLite database.
The URL is taken from ``-x db_url=...`` or the ``RJ_ALEMBIC_DB_URL`` env var;
tests and the engine pass it programmatically.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from redjohn_core.db import meta
from sqlalchemy import engine_from_config, pool

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = meta


def _url() -> str:
    x = context.get_x_argument(as_dictionary=True)
    if "db_url" in x:
        return x["db_url"]
    env = os.environ.get("RJ_ALEMBIC_DB_URL")
    if env:
        return env
    return config.get_main_option("sqlalchemy.url") or "sqlite:///redjohn.db"


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True,
                      dialect_name="sqlite", render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _url()
    connectable = engine_from_config(cfg, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
