import os
from datetime import timedelta


class Config:
    """Базовая конфигурация"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///credentials.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Сессия
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    # Автовыход по бездействию (клиентский JS, минуты; 0 = отключить)
    IDLE_TIMEOUT_MINUTES = int(os.environ.get('IDLE_TIMEOUT_MINUTES', '30'))

    # Rate limiting (логин): хранилище memory:// или redis://...
    RATELIMIT_STORAGE_URI = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
    LOGIN_RATE_LIMIT = os.environ.get('LOGIN_RATE_LIMIT', '10 per minute')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Шифрование
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')

    # Публичные одноразовые ссылки (за reverse-proxy задайте PUBLIC_BASE_URL, например https://vault.example.com)
    PUBLIC_BASE_URL = (os.environ.get('PUBLIC_BASE_URL') or '').rstrip('/')
    OTT_LINK_EXPIRES_HOURS = int(os.environ.get('OTT_LINK_EXPIRES_HOURS', '48'))

    # Почта (SMTP) — задайте в .env или в админке «Почта и Telegram»
    MAIL_SERVER = os.environ.get('MAIL_SERVER', '')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ('1', 'true', 'yes')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', '')

    # Telegram Bot API
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}