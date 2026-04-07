import os

from app import create_app, db
from app.models import User, Credential, CredentialGroup

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_CERT = os.path.join(_BASE_DIR, 'cert.pem')
_KEY = os.path.join(_BASE_DIR, 'key.pem')

app = create_app(os.environ.get('FLASK_ENV', 'development'))

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Credential': Credential, 'CredentialGroup': CredentialGroup}

if __name__ == '__main__':
    ssl_ctx = (_CERT, _KEY) if os.path.isfile(_CERT) and os.path.isfile(_KEY) else None
    if ssl_ctx is None:
        raise SystemExit(
            f'Не найдены cert.pem / key.pem в {_BASE_DIR}. '
            'Сгенерируйте пару или уберите SSL из run.py для HTTP.'
        )
    app.run(
        debug=True,
        host='0.0.0.0',
        port=5003,
        ssl_context=ssl_ctx,
    )