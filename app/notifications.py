import smtplib
from email.mime.text import MIMEText

import requests

from app.delivery_config import (
    get_effective_mail_server,
    get_effective_mail_port,
    get_effective_mail_use_tls,
    get_effective_mail_username,
    get_effective_mail_password,
    get_effective_mail_default_sender,
    get_effective_telegram_token,
    mail_configured,
    telegram_configured,
)


def send_email(to_addr: str, subject: str, body: str) -> None:
    """Отправка письма через SMTP. Настройки — эффективные (БД или env)."""
    server = get_effective_mail_server()
    sender = get_effective_mail_default_sender()
    if not server or not sender:
        raise RuntimeError('Почта не настроена (MAIL_SERVER, MAIL_DEFAULT_SENDER)')

    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = to_addr

    user = get_effective_mail_username()
    password = get_effective_mail_password()
    port = get_effective_mail_port()
    use_tls = get_effective_mail_use_tls()

    with smtplib.SMTP(server, port, timeout=30) as smtp:
        if use_tls:
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.sendmail(sender, [to_addr], msg.as_string())


def send_telegram_message(chat_id: str, text: str) -> None:
    """Отправка сообщения через Telegram Bot API."""
    token = get_effective_telegram_token()
    if not token:
        raise RuntimeError('Telegram не настроен (TELEGRAM_BOT_TOKEN)')

    url = f'https://api.telegram.org/bot{token}/sendMessage'
    r = requests.post(
        url,
        json={'chat_id': chat_id, 'text': text},
        timeout=15,
    )
    data = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
    if not r.ok or not data.get('ok'):
        detail = data.get('description') or r.text or r.reason
        raise RuntimeError(f'Telegram API: {detail}')


__all__ = [
    'send_email',
    'send_telegram_message',
    'mail_configured',
    'telegram_configured',
]
