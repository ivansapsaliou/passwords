"""Добавление колонок в существующую SQLite БД (create_all не делает ALTER)."""

from sqlalchemy import inspect, text


def upgrade_schema(db):
    engine = db.engine
    dialect = engine.dialect.name
    insp = inspect(engine)
    tables = insp.get_table_names()

    if dialect == 'sqlite' and 'user' in tables:
        col_names = {c['name'] for c in insp.get_columns('user')}
        if 'is_admin' not in col_names:
            with engine.begin() as conn:
                conn.execute(
                    text('ALTER TABLE user ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0')
                )

    db.create_all()
