from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from config import config
import os

db = SQLAlchemy()
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
csrf = CSRFProtect()


def _bootstrap_admin():
    """Если в системе ещё нет администратора — назначить BOOTSTRAP_ADMIN_USERNAME."""
    uname = (os.environ.get('BOOTSTRAP_ADMIN_USERNAME') or '').strip()
    if not uname:
        return
    from app.models import User

    if User.query.filter_by(is_admin=True).first():
        return
    u = User.query.filter_by(username=uname).first()
    if u:
        u.is_admin = True
        db.session.commit()


def create_app(config_name=None):
    """Фабрика для создания приложения"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    limiter.init_app(app)
    csrf.init_app(app)

    force_https = not app.config.get('DEBUG', False)
    Talisman(
        app,
        force_https=force_https,
        content_security_policy={
            'default-src': "'self'",
            'script-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            'style-src': "'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
            'font-src': "'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:",
            'img-src': "'self' data: https: blob:",
            # fetch/XHR к CDN (в т.ч. загрузка .map для source maps в DevTools)
            'connect-src': "'self' https://cdn.jsdelivr.net",
        },
        frame_options='DENY',
        referrer_policy='strict-origin-when-cross-origin',
    )

    # Инициализация расширений
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице'

    # Регистрация blueprints
    from app.routes import auth_bp, main_bp, credential_bp, admin_bp, reveal_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(credential_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(reveal_bp)

    # Инициализация БД
    with app.app_context():
        from app.db_upgrade import upgrade_schema

        upgrade_schema(db)
        _bootstrap_admin()

    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))

    @app.errorhandler(404)
    def not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('500.html'), 500

    @app.context_processor
    def inject_idle_timeout():
        return {'idle_timeout_minutes': app.config.get('IDLE_TIMEOUT_MINUTES', 30)}

    @app.cli.command('rotate-encryption')
    def rotate_encryption_command():
        """Перешифровать все поля в формате v1: (сделайте бэкап БД заранее)."""
        from app.models import User, Credential, CredentialHistory, DeliverySettings
        from app.utils import EncryptionManager

        mgr = EncryptionManager()
        for u in User.query.all():
            if u.totp_secret_encrypted:
                plain = mgr.decrypt(u.totp_secret_encrypted)
                u.totp_secret_encrypted = mgr.encrypt(plain)
        for c in Credential.query.all():
            nu = mgr.decrypt(c.username_encrypted)
            np = mgr.decrypt(c.password_encrypted)
            c.username_encrypted = mgr.encrypt(nu)
            c.password_encrypted = mgr.encrypt(np)
            if c.extra_data_encrypted:
                ex = mgr.decrypt(c.extra_data_encrypted)
                c.extra_data_encrypted = mgr.encrypt(ex)
        for h in CredentialHistory.query.all():
            s = mgr.decrypt(h.snapshot_encrypted)
            h.snapshot_encrypted = mgr.encrypt(s)
        row = DeliverySettings.query.get(1)
        if row:
            if row.mail_password_encrypted:
                plain = mgr.decrypt(row.mail_password_encrypted)
                row.mail_password_encrypted = mgr.encrypt(plain)
            if row.telegram_bot_token_encrypted:
                plain = mgr.decrypt(row.telegram_bot_token_encrypted)
                row.telegram_bot_token_encrypted = mgr.encrypt(plain)
        db.session.commit()
        print('rotate-encryption: готово.')

    return app