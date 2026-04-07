"""Разбор CSV для импорта из Bitwarden, Chrome и KeePass-подобных экспортов."""

import csv
import io
import re
from typing import Any, Dict, Generator


def _norm_row(row: Dict[str, Any]) -> Dict[str, str]:
    out = {}
    for k, v in row.items():
        if k is None:
            continue
        key = str(k).strip().lower()
        key = re.sub(r'\s+', '_', key)
        out[key] = (v if v is not None else '').strip()
    return out


def _map_bitwarden(row: Dict[str, str]) -> Dict[str, str]:
    title = row.get('name') or 'Без названия'
    return {
        'title': title[:120],
        'username': row.get('login_username') or row.get('username') or '',
        'password': row.get('login_password') or row.get('password') or '',
        'url': (row.get('login_uri') or row.get('uri') or '')[:255],
        'description': (row.get('notes') or '')[:4000],
    }


def _map_chrome(row: Dict[str, str]) -> Dict[str, str]:
    title = row.get('name') or row.get('title') or 'Без названия'
    return {
        'title': title[:120],
        'username': row.get('username') or row.get('login') or '',
        'password': row.get('password') or '',
        'url': (row.get('url') or '')[:255],
        'description': '',
    }


def _map_keepass(row: Dict[str, str]) -> Dict[str, str]:
    title = row.get('title') or row.get('name') or 'Без названия'
    return {
        'title': title[:120],
        'username': row.get('username') or row.get('user_name') or row.get('login') or '',
        'password': row.get('password') or '',
        'url': (row.get('url') or row.get('website') or row.get('web_site') or '')[:255],
        'description': (row.get('notes') or row.get('comment') or '')[:4000],
    }


_MAPPERS = {
    'bitwarden': _map_bitwarden,
    'chrome': _map_chrome,
    'keepass': _map_keepass,
}


def iter_import_rows(
    raw: bytes,
    format_name: str,
    *,
    max_rows: int = 5000,
) -> Generator[Dict[str, str], None, None]:
    """Итератор нормализованных записей для Credential."""
    mapper = _MAPPERS.get(format_name)
    if not mapper:
        raise ValueError('Неизвестный формат')

    text = raw.decode('utf-8-sig')
    reader = csv.DictReader(io.StringIO(text))
    count = 0
    for row in reader:
        if count >= max_rows:
            break
        norm = _norm_row(row)
        if not any(norm.values()):
            continue
        item = mapper(norm)
        if not item.get('username') and not item.get('password'):
            continue
        count += 1
        yield item
