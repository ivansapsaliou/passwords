from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import config
import os

db = SQLAlchemy()
login_manager = LoginManager()


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

    return app