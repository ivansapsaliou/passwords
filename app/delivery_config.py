"""Эффективные настройки доставки: непустые значения из БД перекрывают env/config."""

from typing import Optional

from flask import current_app

from app.models import DeliverySettings
from app.utils import EncryptionManager


def _encryption():
    return EncryptionManager()


def get_delivery_row() -> Optional[DeliverySettings]:
    return DeliverySettings.query.get(1)


def _cfg_str(key: str) -> str:
    return (current_app.config.get(key) or '').strip()


def _cfg_int(key: str, default: int) -> int:
    v = current_app.config.get(key, default)
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def get_effective_mail_server() -> str:
    row = get_delivery_row()
    if row and (row.mail_server or '').strip():
        return row.mail_server.strip()
    return _cfg_str('MAIL_SERVER')


def get_effective_mail_port() -> int:
    row = get_delivery_row()
    if row and row.mail_port is not None:
        return int(row.mail_port)
    return _cfg_int('MAIL_PORT', 587)


def get_effective_mail_use_tls() -> bool:
    row = get_delivery_row()
    if row and row.mail_use_tls is not None:
        return bool(row.mail_use_tls)
    return bool(current_app.config.get('MAIL_USE_TLS', True))


def get_effective_mail_username() -> str:
    row = get_delivery_row()
    if row and (row.mail_username or '').strip():
        return row.mail_username.strip()
    return _cfg_str('MAIL_USERNAME')


def get_effective_mail_password() -> str:
    row = get_delivery_row()
    if row and (row.mail_password_encrypted or '').strip():
        try:
            return _encryption().decrypt(row.mail_password_encrypted)
        except Exception:
            return ''
    return _cfg_str('MAIL_PASSWORD')


def get_effective_mail_default_sender() -> str:
    row = get_delivery_row()
    if row and (row.mail_default_sender or '').strip():
        return row.mail_default_sender.strip()
    return _cfg_str('MAIL_DEFAULT_SENDER')


def get_effective_telegram_token() -> str:
    row = get_delivery_row()
    if row and (row.telegram_bot_token_encrypted or '').strip():
        try:
            return _encryption().decrypt(row.telegram_bot_token_encrypted)
        except Exception:
            return ''
    return _cfg_str('TELEGRAM_BOT_TOKEN')


def get_effective_public_base_url() -> str:
    row = get_delivery_row()
    if row and (row.public_base_url or '').strip():
        return row.public_base_url.strip().rstrip('/')
    return _cfg_str('PUBLIC_BASE_URL')


def get_effective_ott_hours() -> int:
    row = get_delivery_row()
    if row and row.ott_link_expires_hours is not None:
        return max(1, int(row.ott_link_expires_hours))
    return max(1, _cfg_int('OTT_LINK_EXPIRES_HOURS', 48))


def mail_configured() -> bool:
    return bool(get_effective_mail_server() and get_effective_mail_default_sender())


def telegram_configured() -> bool:
    return bool(get_effective_telegram_token())
