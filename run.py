import os
from app import create_app, db
from app.models import User, Credential, CredentialGroup

app = create_app(os.environ.get('FLASK_ENV', 'development'))

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Credential': Credential, 'CredentialGroup': CredentialGroup}

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5003)