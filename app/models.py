from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
from app.utils import EncryptionManager


class User(UserMixin, db.Model):
    """Модель пользователя"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    totp_secret_encrypted = db.Column(db.Text)  # base32, Fernet

    credentials = db.relationship('Credential', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    groups = db.relationship('CredentialGroup', backref='creator', lazy='dynamic', cascade='all, delete-orphan')
    servers = db.relationship('Server', back_populates='user', lazy='dynamic', cascade='all, delete-orphan')
    shares_received = db.relationship(
        'CredentialShare',
        foreign_keys='CredentialShare.shared_with_user_id',
        back_populates='shared_with_user',
        lazy='dynamic',
    )

    def set_password(self, password):
        """Устанавливает пароль"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Проверяет пароль"""
        return check_password_hash(self.password_hash, password)

    def set_totp_secret(self, raw_base32: str):
        """Сохраняет секрет TOTP (base32)."""
        mgr = EncryptionManager()
        self.totp_secret_encrypted = mgr.encrypt(raw_base32.strip().replace(' ', ''))

    def get_totp_secret_plain(self):
        """Расшифровка секрета TOTP для проверки кода."""
        if not self.totp_secret_encrypted:
            return None
        mgr = EncryptionManager()
        return mgr.decrypt(self.totp_secret_encrypted)

    def clear_totp(self):
        self.totp_enabled = False
        self.totp_secret_encrypted = None

    def __repr__(self):
        return f'<User {self.username}>'


class CredentialGroup(db.Model):
    """Модель группы учетных данных"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    color = db.Column(db.String(7), default='#3b82f6')
    position = db.Column(db.Integer, default=0, nullable=False)

    credentials = db.relationship('Credential', backref='group', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<CredentialGroup {self.name}>'


class Server(db.Model):
    """Сервер (хост): один IP заводится один раз, к нему привязываются учётки."""

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', back_populates='servers')
    credentials = db.relationship('Credential', backref='server', lazy='dynamic')

    __table_args__ = (db.UniqueConstraint('user_id', 'name', name='uq_server_user_name'),)

    def __repr__(self):
        return f'<Server {self.name} {self.ip_address}>'


class Credential(db.Model):
    """Модель для хранения учетных данных"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    service_type = db.Column(db.String(50), nullable=False)  # server, database, app, etc
    description = db.Column(db.Text)

    # Зашифрованные данные
    username_encrypted = db.Column(db.Text, nullable=False)
    password_encrypted = db.Column(db.Text, nullable=False)
    url = db.Column(db.String(255))
    port = db.Column(db.Integer)
    extra_data_encrypted = db.Column(db.Text)  # JSON для доп данных

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('credential_group.id'))
    server_id = db.Column(db.Integer, db.ForeignKey('server.id'))
    position = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)

    shares = db.relationship(
        'CredentialShare',
        back_populates='credential',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )
    reveal_tokens = db.relationship(
        'CredentialRevealToken',
        back_populates='credential',
        lazy='dynamic',
        cascade='all, delete-orphan',
    )

    def set_credentials(self, username, password):
        """Устанавливает и шифрует логин и пароль."""
        manager = EncryptionManager()
        self.username_encrypted = manager.encrypt(username)
        self.password_encrypted = manager.encrypt(password)

    def apply_extra_data(self, extra_data):
        """Сохраняет или очищает доп. поля (dict → JSON и шифрование; None — очистить)."""
        import json
        manager = EncryptionManager()
        if extra_data:
            self.extra_data_encrypted = manager.encrypt(
                json.dumps(extra_data, ensure_ascii=False)
            )
        else:
            self.extra_data_encrypted = None

    def get_username(self):
        """Получает расшифрованное имя пользователя"""
        manager = EncryptionManager()
        return manager.decrypt(self.username_encrypted)

    def get_password(self):
        """Получает расшифрованный пароль"""
        manager = EncryptionManager()
        return manager.decrypt(self.password_encrypted)

    def get_extra_data(self):
        """Получает дополнительные данные"""
        if not self.extra_data_encrypted:
            return {}
        manager = EncryptionManager()
        import json
        return json.loads(manager.decrypt(self.extra_data_encrypted))

    def __repr__(self):
        return f'<Credential {self.title}>'


class CredentialHistory(db.Model):
    """Снимок учётной записи перед изменением (для восстановления)."""

    __tablename__ = 'credential_history'

    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.Integer, db.ForeignKey('credential.id', ondelete='CASCADE'), nullable=False, index=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    snapshot_encrypted = db.Column(db.Text, nullable=False)

    credential = db.relationship('Credential', backref=db.backref('history_versions', lazy='dynamic'))
    created_by = db.relationship('User', foreign_keys=[created_by_user_id])


class CredentialShare(db.Model):
    """Доступ другого пользователя к записи владельца (только чтение / копирование)."""

    __tablename__ = 'credential_share'
    __table_args__ = (
        db.UniqueConstraint('credential_id', 'shared_with_user_id', name='uq_credential_share_user'),
    )

    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.Integer, db.ForeignKey('credential.id', ondelete='CASCADE'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    shared_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    credential = db.relationship('Credential', back_populates='shares')
    shared_with_user = db.relationship('User', foreign_keys=[shared_with_user_id], back_populates='shares_received')
    shared_by_user = db.relationship('User', foreign_keys=[shared_by_user_id])

    def __repr__(self):
        return f'<CredentialShare cred={self.credential_id} user={self.shared_with_user_id}>'


class CredentialRevealToken(db.Model):
    """Одноразовая ссылка на показ логина и пароля (только храним хэш токена)."""

    __tablename__ = 'credential_reveal_token'

    id = db.Column(db.Integer, primary_key=True)
    credential_id = db.Column(db.Integer, db.ForeignKey('credential.id', ondelete='CASCADE'), nullable=False, index=True)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)

    credential = db.relationship('Credential', back_populates='reveal_tokens')
    created_by_user = db.relationship('User', foreign_keys=[created_by_user_id])

    def __repr__(self):
        return f'<CredentialRevealToken cred={self.credential_id} used={self.used_at is not None}>'


class DeliverySettings(db.Model):
    """Единственная строка настроек доставки (SMTP, Telegram, URL для OTT). Пустое поле в БД = взять из env/config."""

    __tablename__ = 'delivery_settings'

    id = db.Column(db.Integer, primary_key=True)
    mail_server = db.Column(db.String(255))
    mail_port = db.Column(db.Integer)
    mail_use_tls = db.Column(db.Boolean)
    mail_username = db.Column(db.String(255))
    mail_default_sender = db.Column(db.String(255))
    mail_password_encrypted = db.Column(db.Text)
    telegram_bot_token_encrypted = db.Column(db.Text)
    public_base_url = db.Column(db.String(512))
    ott_link_expires_hours = db.Column(db.Integer)

    def __repr__(self):
        return '<DeliverySettings id=1>'


class AuditLog(db.Model):
    """Журнал действий для администраторов (аудит)."""

    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)
    action = db.Column(db.String(64), nullable=False, index=True)
    summary = db.Column(db.Text, nullable=False)
    details_json = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(512))

    actor = db.relationship('User', foreign_keys=[actor_user_id])

    def __repr__(self):
        return f'<AuditLog {self.action} {self.created_at}>'