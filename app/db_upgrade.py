"""Добавление колонок в существующую SQLite БД (create_all не делает ALTER)."""

from sqlalchemy import inspect, text


def _sqlite_user_email_unique(engine) -> bool:
    with engine.connect() as conn:
        indexes = conn.execute(text("PRAGMA index_list('user')")).fetchall()
        for idx in indexes:
            # PRAGMA index_list: seq, name, unique, origin, partial
            idx_name = idx[1]
            is_unique = bool(idx[2])
            if not is_unique:
                continue
            cols = conn.execute(text(f"PRAGMA index_info('{idx_name}')")).fetchall()
            if any((c[2] or '').lower() == 'email' for c in cols):
                return True
    return False


def _drop_user_email_unique_sqlite(engine) -> None:
    with engine.begin() as conn:
        conn.execute(text('PRAGMA foreign_keys=OFF'))
        conn.execute(text('ALTER TABLE user RENAME TO user_old'))
        conn.execute(
            text(
                '''
                CREATE TABLE user (
                    id INTEGER NOT NULL PRIMARY KEY,
                    username VARCHAR(80) NOT NULL UNIQUE,
                    email VARCHAR(120) NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at DATETIME,
                    last_login DATETIME,
                    is_active BOOLEAN,
                    is_admin BOOLEAN NOT NULL DEFAULT 0,
                    totp_enabled BOOLEAN NOT NULL DEFAULT 0,
                    totp_secret_encrypted TEXT
                )
                '''
            )
        )
        conn.execute(
            text(
                '''
                INSERT INTO user (
                    id, username, email, password_hash, created_at, last_login,
                    is_active, is_admin, totp_enabled, totp_secret_encrypted
                )
                SELECT
                    id, username, email, password_hash, created_at, last_login,
                    is_active, is_admin, totp_enabled, totp_secret_encrypted
                FROM user_old
                '''
            )
        )
        conn.execute(text('DROP TABLE user_old'))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_user_email ON user (email)'))
        conn.execute(text('PRAGMA foreign_keys=ON'))


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
        if 'totp_enabled' not in col_names:
            with engine.begin() as conn:
                conn.execute(
                    text('ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0')
                )
        if 'totp_secret_encrypted' not in col_names:
            with engine.begin() as conn:
                conn.execute(text('ALTER TABLE user ADD COLUMN totp_secret_encrypted TEXT'))
        if _sqlite_user_email_unique(engine):
            _drop_user_email_unique_sqlite(engine)

    if dialect == 'sqlite' and 'credential_group' in tables:
        col_names = {c['name'] for c in insp.get_columns('credential_group')}
        if 'position' not in col_names:
            with engine.begin() as conn:
                conn.execute(
                    text('ALTER TABLE credential_group ADD COLUMN position INTEGER NOT NULL DEFAULT 0')
                )

    if dialect == 'sqlite' and 'credential' in tables:
        col_names = {c['name'] for c in insp.get_columns('credential')}
        if 'position' not in col_names:
            with engine.begin() as conn:
                conn.execute(text('ALTER TABLE credential ADD COLUMN position INTEGER NOT NULL DEFAULT 0'))

    db.create_all()

    if dialect == 'sqlite':
        with engine.begin() as conn:
            conn.execute(text('UPDATE credential_group SET position = id WHERE position = 0'))
            conn.execute(text('UPDATE credential SET position = id WHERE position = 0'))
