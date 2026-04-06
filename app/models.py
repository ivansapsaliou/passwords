from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from datetime import datetime
from app.utils import EncryptionManager


class User(UserMixin, db.Model):
    """Модель пользователя"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    credentials = db.relationship('Credential', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    groups = db.relationship('CredentialGroup', backref='creator', lazy='dynamic', cascade='all, delete-orphan')

    def set_password(self, password):
        """Устанавливает пароль"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Проверяет пароль"""
        return check_password_hash(self.password_hash, password)

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

    credentials = db.relationship('Credential', backref='group', lazy='dynamic', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<CredentialGroup {self.name}>'


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

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)

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