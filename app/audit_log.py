"""Запись событий в журнал аудита (админский просмотр)."""

import json
from typing import Any, Mapping, Optional

from flask import has_request_context, request

from app import db
from app.models import AuditLog

ACTION_LOGIN = 'login'
ACTION_LOGOUT = 'logout'
ACTION_USER_CREATED = 'user_created'
ACTION_USER_UPDATED = 'user_updated'
ACTION_DELIVERY_SETTINGS = 'delivery_settings'
ACTION_CREDENTIAL_CREATED = 'credential_created'
ACTION_CREDENTIAL_UPDATED = 'credential_updated'
ACTION_CREDENTIAL_DELETED = 'credential_deleted'
ACTION_SHARE_GRANTED = 'share_granted'
ACTION_SHARE_REVOKED = 'share_revoked'
ACTION_OTT_SENT = 'ott_sent'
ACTION_OTT_CONSUMED = 'ott_consumed'
ACTION_GROUP_CREATED = 'group_created'
ACTION_GROUP_UPDATED = 'group_updated'
ACTION_GROUP_DELETED = 'group_deleted'
ACTION_PASSWORD_CHANGED = 'password_changed'
ACTION_CREDENTIAL_FIELD_COPIED = 'credential_field_copied'
ACTION_TOTP_ENABLED = 'totp_enabled'
ACTION_TOTP_DISABLED = 'totp_disabled'
ACTION_TOTP_REISSUED = 'totp_reissued'
ACTION_CREDENTIALS_IMPORTED = 'credentials_imported'
ACTION_CREDENTIALS_EXPORTED = 'credentials_exported'

ACTION_LABELS = {
    ACTION_LOGIN: 'Вход в систему',
    ACTION_LOGOUT: 'Выход',
    ACTION_USER_CREATED: 'Создан пользователь',
    ACTION_USER_UPDATED: 'Изменён пользователь',
    ACTION_DELIVERY_SETTINGS: 'Настройки доставки',
    ACTION_CREDENTIAL_CREATED: 'Создана запись учётных данных',
    ACTION_CREDENTIAL_UPDATED: 'Обновлена запись',
    ACTION_CREDENTIAL_DELETED: 'Удалена запись',
    ACTION_SHARE_GRANTED: 'Выдан общий доступ',
    ACTION_SHARE_REVOKED: 'Отозван доступ',
    ACTION_OTT_SENT: 'Отправлена одноразовая ссылка',
    ACTION_OTT_CONSUMED: 'Использована одноразовая ссылка',
    ACTION_GROUP_CREATED: 'Создана группа',
    ACTION_GROUP_UPDATED: 'Изменена группа',
    ACTION_GROUP_DELETED: 'Удалена группа',
    ACTION_PASSWORD_CHANGED: 'Смена своего пароля',
    ACTION_CREDENTIAL_FIELD_COPIED: 'Скопировано поле записи',
    ACTION_TOTP_ENABLED: 'Включена двухфакторная аутентификация',
    ACTION_TOTP_DISABLED: 'Отключена двухфакторная аутентификация',
    ACTION_TOTP_REISSUED: 'Администратор перевыпустил 2FA QR',
    ACTION_CREDENTIALS_IMPORTED: 'Импорт учётных записей из CSV',
    ACTION_CREDENTIALS_EXPORTED: 'Экспорт учётных записей в CSV',
}

ALL_ACTIONS = list(ACTION_LABELS.keys())


def record_audit(
    actor_user_id: Optional[int],
    action: str,
    summary: str,
    details: Optional[Mapping[str, Any]] = None,
) -> None:
    """Добавляет запись в текущую сессию БД (без commit)."""
    row = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        summary=(summary or '')[:4000],
        details_json=json.dumps(details, ensure_ascii=False, default=str) if details else None,
    )
    if has_request_context():
        if request.remote_addr:
            row.ip_address = request.remote_addr[:45]
        ua = request.user_agent
        if ua and ua.string:
            row.user_agent = ua.string[:512]
    db.session.add(row)
