import base64
import csv
import hashlib
import io
import json
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    current_app,
    session,
    Response,
)
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import or_, nulls_last, update, func
from sqlalchemy.orm import joinedload

from app import db, limiter
from app.models import (
    User,
    Credential,
    CredentialGroup,
    CredentialHistory,
    CredentialShare,
    CredentialRevealToken,
    DeliverySettings,
    AuditLog,
)
import pyotp
import qrcode

from app.forms import (
    LoginForm,
    TotpLoginForm,
    TotpSetupForm,
    TotpDisableForm,
    ImportCsvForm,
    RestoreForm,
    CredentialForm,
    GroupForm,
    ShareCredentialForm,
    ChangePasswordForm,
    AdminCreateUserForm,
    AdminEditUserForm,
    OneTimeLinkForm,
    AdminDeliverySettingsForm,
    AccountOnboardingForm,
)
from app.notifications import send_email, send_telegram_message, mail_configured, telegram_configured
from app.delivery_config import (
    get_delivery_row,
    get_effective_mail_server,
    get_effective_mail_port,
    get_effective_mail_username,
    get_effective_mail_default_sender,
    get_effective_public_base_url,
    get_effective_ott_hours,
)
from app.utils import EncryptionManager
from app.csv_import import iter_import_rows
from app.audit_log import (
    record_audit,
    ACTION_LOGIN,
    ACTION_LOGOUT,
    ACTION_USER_CREATED,
    ACTION_USER_UPDATED,
    ACTION_DELIVERY_SETTINGS,
    ACTION_CREDENTIAL_CREATED,
    ACTION_CREDENTIAL_UPDATED,
    ACTION_CREDENTIAL_DELETED,
    ACTION_SHARE_GRANTED,
    ACTION_SHARE_REVOKED,
    ACTION_OTT_SENT,
    ACTION_OTT_CONSUMED,
    ACTION_GROUP_CREATED,
    ACTION_GROUP_UPDATED,
    ACTION_GROUP_DELETED,
    ACTION_PASSWORD_CHANGED,
    ACTION_CREDENTIAL_FIELD_COPIED,
    ACTION_TOTP_ENABLED,
    ACTION_TOTP_DISABLED,
    ACTION_TOTP_REISSUED,
    ACTION_CREDENTIALS_IMPORTED,
    ACTION_CREDENTIALS_EXPORTED,
    ACTION_LABELS,
    ALL_ACTIONS,
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
main_bp = Blueprint('main', __name__)
credential_bp = Blueprint('credential_bp', __name__, url_prefix='/credentials')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
reveal_bp = Blueprint('reveal', __name__)


def _login_rate_limit():
    return current_app.config.get('LOGIN_RATE_LIMIT', '10 per minute')


def _ott_token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _onboarding_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt='account-onboarding-v1')


def _onboarding_hash_marker(user: User) -> str:
    return hashlib.sha256((user.password_hash or '').encode('utf-8')).hexdigest()[:16]


def _generate_onboarding_token(user: User) -> str:
    payload = {
        'kind': 'onboarding',
        'uid': user.id,
        'ph': _onboarding_hash_marker(user),
    }
    return _onboarding_serializer().dumps(payload)


def _build_onboarding_link(token: str) -> str:
    base = get_effective_public_base_url() or request.url_root.rstrip('/')
    return f"{base}{url_for('auth.account_onboarding', token=token)}"


def _totp_qr_data(secret: str, email: str):
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name='SecureVault')
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return uri, qr_b64


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login', next=request.path))
        if not getattr(current_user, 'is_admin', False):
            flash('Нужны права администратора', 'danger')
            return redirect(url_for('main.dashboard'))
        return view(*args, **kwargs)

    return wrapped


def _extra_from_form(form):
    if not form.extra_data_json.data or not str(form.extra_data_json.data).strip():
        return None
    return json.loads(form.extra_data_json.data)


def _visible_credentials_query(user):
    """Свои записи и те, что расшарены текущему пользователю."""
    share_ids = db.session.query(CredentialShare.credential_id).filter(
        CredentialShare.shared_with_user_id == user.id
    )
    return Credential.query.filter(
        or_(Credential.user_id == user.id, Credential.id.in_(share_ids))
    )


def _credential_access(user, credential):
    """'owner' | 'shared' | None"""
    if credential.user_id == user.id:
        return 'owner'
    if db.session.query(CredentialShare.id).filter_by(
        credential_id=credential.id,
        shared_with_user_id=user.id,
    ).first():
        return 'shared'
    return None


def _snapshot_credential_plain(credential):
    return {
        'title': credential.title,
        'service_type': credential.service_type,
        'description': credential.description,
        'username': credential.get_username(),
        'password': credential.get_password(),
        'url': credential.url,
        'port': credential.port,
        'group_id': credential.group_id,
        'extra_data': credential.get_extra_data(),
    }


def _append_credential_history(credential, user_id):
    mgr = EncryptionManager()
    snap = _snapshot_credential_plain(credential)
    row = CredentialHistory(
        credential_id=credential.id,
        created_by_user_id=user_id,
        snapshot_encrypted=mgr.encrypt(json.dumps(snap, ensure_ascii=False)),
    )
    db.session.add(row)


# ===== Публичная одноразовая ссылка =====
@reveal_bp.route('/r/<path:token>')
def reveal_consume(token):
    """Один успешный просмотр логина и пароля по токену; затем ссылка блокируется."""
    raw = (token or '').strip()
    if not raw:
        return render_template('reveal_invalid.html', reason='missing'), 404

    token_hash = _ott_token_hash(raw)
    now = datetime.utcnow()
    stmt = (
        update(CredentialRevealToken)
        .where(
            CredentialRevealToken.token_hash == token_hash,
            CredentialRevealToken.used_at.is_(None),
            CredentialRevealToken.expires_at > now,
        )
        .values(used_at=now)
    )
    result = db.session.execute(stmt)
    if result.rowcount != 1:
        db.session.rollback()
        return render_template('reveal_invalid.html', reason='expired_or_used'), 410

    db.session.commit()
    row = (
        CredentialRevealToken.query.options(
            joinedload(CredentialRevealToken.credential),
            joinedload(CredentialRevealToken.created_by_user),
        )
        .filter_by(token_hash=token_hash)
        .first()
    )
    if not row or not row.credential:
        return render_template('reveal_invalid.html', reason='not_found'), 410

    cred = row.credential
    creator = row.created_by_user
    creator_username = creator.username if creator else None
    record_audit(
        None,
        ACTION_OTT_CONSUMED,
        f'Одноразовая ссылка открыта: «{cred.title}»',
        {
            'credential_id': cred.id,
            'reveal_token_id': row.id,
            'created_by_user_id': row.created_by_user_id,
        },
    )
    db.session.commit()
    return render_template(
        'reveal_public.html',
        credential_title=cred.title,
        plaintext_username=cred.get_username(),
        plaintext_password=cred.get_password(),
        creator_username=creator_username,
    )


# ===== Аутентификация =====
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Публичная регистрация отключена — пользователей создаёт администратор."""
    flash('Регистрация отключена. Обратитесь к администратору системы.', 'warning')
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit(_login_rate_limit, methods=['POST'])
def login():
    """Вход пользователя"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            if not user.is_active:
                flash('Учётная запись отключена. Обратитесь к администратору.', 'danger')
                return render_template('login.html', form=form)
            if user.totp_enabled and user.get_totp_secret_plain():
                session['pending_totp_user_id'] = user.id
                session.permanent = True
                return redirect(url_for('auth.verify_totp_login'))
            login_user(user, remember=True)
            session.permanent = True
            user.last_login = datetime.utcnow()
            record_audit(user.id, ACTION_LOGIN, f'Вход: {user.username}')
            db.session.commit()

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash('Неверное имя или пароль', 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/login/totp', methods=['GET', 'POST'])
def verify_totp_login():
    """Второй фактор после успешного пароля."""
    uid = session.get('pending_totp_user_id')
    if not uid:
        return redirect(url_for('auth.login'))
    user = User.query.get(uid)
    if not user or not user.totp_enabled:
        session.pop('pending_totp_user_id', None)
        return redirect(url_for('auth.login'))

    secret = user.get_totp_secret_plain()
    if not secret:
        session.pop('pending_totp_user_id', None)
        flash('Ошибка настроек 2FA. Обратитесь к администратору.', 'danger')
        return redirect(url_for('auth.login'))

    form = TotpLoginForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(secret)
        if totp.verify(form.code.data, valid_window=1):
            session.pop('pending_totp_user_id', None)
            login_user(user, remember=True)
            session.permanent = True
            user.last_login = datetime.utcnow()
            record_audit(user.id, ACTION_LOGIN, f'Вход (2FA): {user.username}')
            db.session.commit()
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        flash('Неверный код', 'danger')

    return render_template('auth_totp_login.html', form=form, username=user.username)


@auth_bp.route('/onboarding/<token>', methods=['GET', 'POST'])
def account_onboarding(token):
    max_age = int(current_app.config.get('ONBOARDING_LINK_TTL_SECONDS', 60 * 60 * 24 * 3))
    try:
        payload = _onboarding_serializer().loads(token, max_age=max_age)
    except SignatureExpired:
        flash('Ссылка истекла. Обратитесь к администратору за новой.', 'danger')
        return redirect(url_for('auth.login'))
    except BadSignature:
        flash('Некорректная ссылка onboarding.', 'danger')
        return redirect(url_for('auth.login'))

    if payload.get('kind') != 'onboarding':
        flash('Некорректный тип ссылки onboarding.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.get(payload.get('uid'))
    if not user or not user.is_active:
        flash('Учётная запись недоступна.', 'danger')
        return redirect(url_for('auth.login'))
    if payload.get('ph') != _onboarding_hash_marker(user):
        flash('Ссылка уже использована. Обратитесь к администратору за новой.', 'warning')
        return redirect(url_for('auth.login'))

    secret = user.get_totp_secret_plain()
    if not user.totp_enabled or not secret:
        flash('2FA для учётной записи не настроена. Обратитесь к администратору.', 'danger')
        return redirect(url_for('auth.login'))

    form = AccountOnboardingForm()
    otpauth_uri, qr_b64 = _totp_qr_data(secret, user.email)
    if form.validate_on_submit():
        user.set_password(form.new_password.data)
        db.session.commit()
        flash('Пароль сохранён. Используйте логин/пароль и код из Authenticator для входа.', 'success')
        return redirect(url_for('auth.login'))
    return render_template(
        'auth_onboarding.html',
        form=form,
        onboarding_user=user,
        qr_b64=qr_b64,
        secret_manual=secret,
        otpauth_uri=otpauth_uri,
        hide_app_shell=True,
    )


@auth_bp.route('/totp/setup', methods=['GET', 'POST'])
@login_required
def totp_setup():
    """Включение TOTP: QR и подтверждение кода."""
    if current_user.totp_enabled:
        flash('Двухфакторная аутентификация уже включена.', 'info')
        return redirect(url_for('main.profile'))

    if request.method == 'GET':
        secret = pyotp.random_base32()
        session['totp_setup_secret'] = secret
        session.modified = True
    else:
        secret = session.get('totp_setup_secret')
        if not secret:
            flash('Сессия истекла. Обновите страницу.', 'warning')
            return redirect(url_for('auth.totp_setup'))

    form = TotpSetupForm()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name='SecureVault',
    )
    buf = io.BytesIO()
    qrcode.make(uri).save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('ascii')

    if form.validate_on_submit():
        if not pyotp.TOTP(secret).verify(form.code.data, valid_window=1):
            flash('Неверный код', 'danger')
            return render_template(
                'totp_setup.html',
                form=form,
                qr_b64=qr_b64,
                otpauth_uri=uri,
                secret_manual=secret,
            )
        current_user.set_totp_secret(secret)
        current_user.totp_enabled = True
        session.pop('totp_setup_secret', None)
        record_audit(
            current_user.id,
            ACTION_TOTP_ENABLED,
            f'Включена 2FA: {current_user.username}',
        )
        db.session.commit()
        flash('Двухфакторная аутентификация включена.', 'success')
        return redirect(url_for('main.profile'))

    return render_template(
        'totp_setup.html',
        form=form,
        qr_b64=qr_b64,
        otpauth_uri=uri,
        secret_manual=secret,
    )


@auth_bp.route('/totp/disable', methods=['GET', 'POST'])
@login_required
def totp_disable():
    """Отключение 2FA."""
    if not current_user.totp_enabled:
        flash('2FA не была включена.', 'info')
        return redirect(url_for('main.profile'))

    form = TotpDisableForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.password.data):
            flash('Неверный пароль', 'danger')
        else:
            code = (form.code.data or '').replace(' ', '').strip()
            secret = current_user.get_totp_secret_plain()
            if not secret or not pyotp.TOTP(secret).verify(code, valid_window=1):
                flash('Неверный код из приложения-аутентификатора', 'danger')
            else:
                current_user.clear_totp()
                record_audit(
                    current_user.id,
                    ACTION_TOTP_DISABLED,
                    f'Отключена 2FA: {current_user.username}',
                )
                db.session.commit()
                flash('Двухфакторная аутентификация отключена.', 'success')
                return redirect(url_for('main.profile'))

    return render_template('totp_disable.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Выход пользователя"""
    uid = current_user.id
    uname = current_user.username
    record_audit(uid, ACTION_LOGOUT, f'Выход: {uname}')
    db.session.commit()
    logout_user()
    flash('Вы вышли из аккаунта', 'info')
    return redirect(url_for('main.index'))


# ===== Основные маршруты =====
@main_bp.route('/')
def index():
    """Главная страница"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Панель управления"""
    groups = current_user.groups.order_by(CredentialGroup.position, CredentialGroup.name).all()
    visible = _visible_credentials_query(current_user)
    total_credentials = visible.count()
    total_groups = len(groups)

    recent_credentials = visible.order_by(nulls_last(Credential.last_accessed.desc())).limit(5).all()

    service_types = {}
    for cred in visible.all():
        service_types[cred.service_type] = service_types.get(cred.service_type, 0) + 1

    return render_template(
        'dashboard.html',
        groups=groups,
        total_credentials=total_credentials,
        total_groups=total_groups,
        recent_credentials=recent_credentials,
        service_types=service_types,
    )


@main_bp.route('/profile')
@login_required
def profile():
    """Профиль пользователя"""
    return render_template('profile.html')


@main_bp.route('/api/search')
@login_required
def api_search_credentials():
    """Список записей для быстрого поиска (Cmd+K)."""
    q = (request.args.get('q') or '').strip()
    if len(q) < 2:
        return jsonify({'results': []})
    query = _visible_credentials_query(current_user)
    pat = f'%{q}%'
    query = query.filter(
        or_(Credential.title.ilike(pat), Credential.description.ilike(pat))
    )
    rows = (
        query.options(joinedload(Credential.group))
        .order_by(Credential.title)
        .limit(25)
        .all()
    )
    return jsonify(
        {
            'results': [
                {
                    'id': c.id,
                    'title': c.title,
                    'group_name': c.group.name if c.group else None,
                    'url': c.url or '',
                }
                for c in rows
            ]
        }
    )


# ===== Администрирование =====
@admin_bp.route('/users')
@login_required
@admin_required
def admin_user_list():
    users = User.query.order_by(User.username).all()
    return render_template('admin_users.html', users=users)


@admin_bp.route('/audit-log')
@login_required
@admin_required
def admin_audit_log():
    """Журнал действий (аудит) для администраторов."""
    page = request.args.get('page', 1, type=int)
    action_filter = (request.args.get('action') or '').strip()
    q = (request.args.get('q') or '').strip()

    query = AuditLog.query.options(joinedload(AuditLog.actor)).order_by(AuditLog.created_at.desc())
    if action_filter in ALL_ACTIONS:
        query = query.filter(AuditLog.action == action_filter)
    if q:
        pat = f'%{q}%'
        query = query.filter(or_(AuditLog.summary.ilike(pat), AuditLog.details_json.ilike(pat)))

    logs = query.paginate(page=page, per_page=40)
    return render_template(
        'admin_audit_log.html',
        logs=logs,
        action_filter=action_filter,
        q=q,
        action_labels=ACTION_LABELS,
        all_actions=ALL_ACTIONS,
    )


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_create():
    form = AdminCreateUserForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data.strip(),
            email=form.email.data.strip(),
            is_admin=bool(form.grant_admin.data),
        )
        user.set_password(secrets.token_urlsafe(24))
        user.totp_enabled = True
        user.set_totp_secret(pyotp.random_base32())
        db.session.add(user)
        db.session.flush()
        onboarding_token = _generate_onboarding_token(user)
        onboarding_link = _build_onboarding_link(onboarding_token)
        subject = 'SecureVault: ваш доступ создан'
        text_body = render_template(
            'emails/onboarding_user.txt',
            username=user.username,
            onboarding_link=onboarding_link,
        )
        html_body = render_template(
            'emails/onboarding_user.html',
            username=user.username,
            onboarding_link=onboarding_link,
        )
        try:
            send_email(user.email, subject, text_body, html_body=html_body)
        except Exception as ex:
            db.session.rollback()
            flash(f'Пользователь не создан: не удалось отправить onboarding email ({ex})', 'danger')
            return render_template('admin_user_create.html', form=form)
        record_audit(
            current_user.id,
            ACTION_USER_CREATED,
            f'Создан пользователь «{user.username}»',
            {
                'new_user_id': user.id,
                'email': user.email,
                'is_admin': user.is_admin,
                'totp_enabled': user.totp_enabled,
            },
        )
        db.session.commit()
        flash(f'Пользователь «{user.username}» создан, письмо с инструкцией отправлено.', 'success')
        return redirect(url_for('admin.admin_user_list'))

    return render_template('admin_user_create.html', form=form)


@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_user_edit(user_id):
    user = User.query.get_or_404(user_id)
    form = AdminEditUserForm(user_id=user.id)

    if form.validate_on_submit():
        if user.id == current_user.id:
            if not form.is_active.data:
                flash('Нельзя деактивировать свою учётную запись.', 'danger')
                return render_template('admin_user_edit.html', form=form, edit_user=user)
            if not form.grant_admin.data and user.is_admin:
                other_admins = User.query.filter(User.is_admin.is_(True), User.id != user.id).count()
                if other_admins == 0:
                    flash('Нельзя снять с себя права администратора, пока нет другого администратора.', 'danger')
                    return render_template('admin_user_edit.html', form=form, edit_user=user)

        user.username = form.username.data.strip()
        user.email = form.email.data.strip()
        user.is_active = bool(form.is_active.data)
        user.is_admin = bool(form.grant_admin.data)
        if form.new_password.data:
            user.set_password(form.new_password.data)
        record_audit(
            current_user.id,
            ACTION_USER_UPDATED,
            f'Обновлён пользователь «{user.username}»',
            {
                'user_id': user.id,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'password_changed': bool(form.new_password.data),
            },
        )
        db.session.commit()
        flash(f'Данные пользователя «{user.username}» сохранены.', 'success')
        return redirect(url_for('admin.admin_user_list'))

    if request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.is_active.data = user.is_active
        form.grant_admin.data = user.is_admin

    return render_template('admin_user_edit.html', form=form, edit_user=user)


@admin_bp.route('/users/<int:user_id>/totp/reissue', methods=['POST'])
@login_required
@admin_required
def admin_user_reissue_totp(user_id):
    user = User.query.get_or_404(user_id)
    if not user.is_active:
        flash('Нельзя перевыпустить 2FA для отключённой учётной записи.', 'danger')
        return redirect(url_for('admin.admin_user_edit', user_id=user.id))
    if not user.email:
        flash('У пользователя не задан email для отправки инструкции.', 'danger')
        return redirect(url_for('admin.admin_user_edit', user_id=user.id))

    new_secret = pyotp.random_base32()
    user.set_totp_secret(new_secret)
    user.totp_enabled = True
    onboarding_token = _generate_onboarding_token(user)
    onboarding_link = _build_onboarding_link(onboarding_token)
    subject = 'SecureVault: перевыпуск QR-кода 2FA'
    text_body = render_template(
        'emails/reissue_totp.txt',
        username=user.username,
        onboarding_link=onboarding_link,
    )
    html_body = render_template(
        'emails/reissue_totp.html',
        username=user.username,
        onboarding_link=onboarding_link,
    )
    try:
        send_email(user.email, subject, text_body, html_body=html_body)
    except Exception as ex:
        db.session.rollback()
        flash(f'Не удалось отправить письмо пользователю: {ex}', 'danger')
        return redirect(url_for('admin.admin_user_edit', user_id=user.id))

    record_audit(
        current_user.id,
        ACTION_TOTP_REISSUED,
        f'Перевыпущен 2FA QR для «{user.username}»',
        {'user_id': user.id, 'email': user.email},
    )
    db.session.commit()
    flash('Новый QR перевыпущен. Старый код инвалидирован; пользователю отправлено письмо.', 'success')
    return redirect(url_for('admin.admin_user_edit', user_id=user.id))


def _ensure_delivery_row():
    r = DeliverySettings.query.get(1)
    if r is None:
        r = DeliverySettings(id=1)
        db.session.add(r)
        db.session.commit()
    return r


@admin_bp.route('/settings/delivery', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_delivery_settings():
    row = get_delivery_row()
    form = AdminDeliverySettingsForm()

    if request.method == 'GET':
        form.mail_server.data = get_effective_mail_server() or ''
        form.mail_port.data = get_effective_mail_port()
        if row is None or row.mail_use_tls is None:
            form.mail_tls_mode.data = 'env'
        else:
            form.mail_tls_mode.data = 'yes' if row.mail_use_tls else 'no'
        form.mail_username.data = get_effective_mail_username() or ''
        form.mail_default_sender.data = get_effective_mail_default_sender() or ''
        pub = get_effective_public_base_url()
        form.public_base_url.data = pub or ''
        form.ott_link_expires_hours.data = get_effective_ott_hours()

    mail_on = mail_configured()
    tg_on = telegram_configured()

    if form.validate_on_submit():
        rec = _ensure_delivery_row()
        rec.mail_server = (form.mail_server.data or '').strip() or None
        if form.mail_port.data is not None and form.mail_port.data > 0:
            rec.mail_port = int(form.mail_port.data)
        else:
            rec.mail_port = None
        if form.mail_tls_mode.data == 'env':
            rec.mail_use_tls = None
        elif form.mail_tls_mode.data == 'yes':
            rec.mail_use_tls = True
        else:
            rec.mail_use_tls = False
        rec.mail_username = (form.mail_username.data or '').strip() or None
        rec.mail_default_sender = (form.mail_default_sender.data or '').strip() or None
        if form.mail_password_new.data:
            rec.mail_password_encrypted = EncryptionManager().encrypt(form.mail_password_new.data)
        if (form.telegram_bot_token_new.data or '').strip():
            rec.telegram_bot_token_encrypted = EncryptionManager().encrypt(
                form.telegram_bot_token_new.data.strip()
            )
        rec.public_base_url = (form.public_base_url.data or '').strip() or None
        if form.ott_link_expires_hours.data is not None and form.ott_link_expires_hours.data > 0:
            rec.ott_link_expires_hours = int(form.ott_link_expires_hours.data)
        else:
            rec.ott_link_expires_hours = None
        record_audit(
            current_user.id,
            ACTION_DELIVERY_SETTINGS,
            'Сохранены настройки почты, Telegram и публичных ссылок',
        )
        db.session.commit()
        flash('Настройки доставки сохранены.', 'success')
        return redirect(url_for('admin.admin_delivery_settings'))

    row = get_delivery_row()
    return render_template(
        'admin_delivery_settings.html',
        form=form,
        mail_on=mail_on,
        telegram_on=tg_on,
        mail_pwd_in_db=bool(row and (row.mail_password_encrypted or '').strip()),
        tg_token_in_db=bool(row and (row.telegram_bot_token_encrypted or '').strip()),
    )


@main_bp.route('/settings/password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Смена пароля"""
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Неверный текущий пароль', 'danger')
        else:
            current_user.set_password(form.new_password.data)
            db.session.commit()
            flash('Пароль успешно обновлён', 'success')
            return redirect(url_for('main.profile'))

    return render_template('settings_password.html', form=form)


# ===== Управление учетными данными =====
@credential_bp.route('/api/users-for-share')
@login_required
def users_for_share():
    """До 10 пользователей для выбора при расшаривании (подстрока в имени или первые по алфавиту)."""
    q = (request.args.get('q') or '').strip()
    credential_id = request.args.get('credential_id', type=int)
    limit = 10

    exclude = {current_user.id}
    if credential_id:
        cred = Credential.query.get(credential_id)
        if cred and cred.user_id == current_user.id:
            rows = db.session.query(CredentialShare.shared_with_user_id).filter_by(
                credential_id=credential_id
            ).all()
            exclude.update(r[0] for r in rows)

    user_query = User.query.filter(User.is_active.is_(True)).filter(~User.id.in_(exclude))
    if q:
        user_query = user_query.filter(User.username.ilike(f'%{q}%'))
    users = user_query.order_by(User.username).limit(limit).all()
    return jsonify({'users': [{'id': u.id, 'username': u.username} for u in users]})


@credential_bp.route('/')
@login_required
def list_credentials():
    """Список всех учетных данных"""
    page = request.args.get('page', 1, type=int)
    group_id = request.args.get('group_id', None, type=int)
    search = request.args.get('search', '')

    query = _visible_credentials_query(current_user)

    if group_id:
        query = query.filter_by(group_id=group_id)

    if search:
        query = query.filter(Credential.title.ilike(f'%{search}%'))

    credentials = (
        query.order_by(
            nulls_last(Credential.group_id),
            Credential.position.asc(),
            Credential.title.asc(),
        ).paginate(page=page, per_page=10)
    )
    groups = current_user.groups.order_by(CredentialGroup.position, CredentialGroup.name).all()
    groups_meta = [{'group': g, 'count': g.credentials.count()} for g in groups]

    return render_template(
        'credentials.html',
        credentials=credentials,
        groups=groups,
        groups_meta=groups_meta,
        search=search,
        group_id=group_id,
        can_sort_credentials=bool(group_id) and not bool(search),
    )


@credential_bp.route('/export', methods=['GET'])
@login_required
def export_credentials_csv():
    """Экспорт своих записей в CSV (пароли в открытом виде — только по доверенному каналу)."""
    owned = Credential.query.filter_by(user_id=current_user.id).order_by(Credential.title).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['title', 'username', 'password', 'url', 'port', 'description'])
    for c in owned:
        desc = (c.description or '').replace('\r\n', ' ').replace('\n', ' ')
        writer.writerow(
            [
                c.title,
                c.get_username(),
                c.get_password(),
                c.url or '',
                c.port if c.port is not None else '',
                desc,
            ]
        )
    record_audit(
        current_user.id,
        ACTION_CREDENTIALS_EXPORTED,
        f'Экспорт CSV: {len(owned)} записей',
        {'count': len(owned)},
    )
    db.session.commit()
    return Response(
        '\ufeff' + buf.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': 'attachment; filename=securevault_export.csv'},
    )


@credential_bp.route('/import', methods=['GET', 'POST'])
@login_required
def import_credentials_csv():
    """Импорт из CSV (Bitwarden, Chrome, KeePass-подобный)."""
    form = ImportCsvForm()
    if form.validate_on_submit():
        raw = form.file.data.read()
        if len(raw) > 5 * 1024 * 1024:
            flash('Файл больше 5 МБ — не импортирован.', 'danger')
            return render_template('import_credentials.html', form=form)
        try:
            items = list(iter_import_rows(raw, form.format.data))
        except (UnicodeDecodeError, ValueError) as e:
            flash(f'Не удалось прочитать CSV: {e}', 'danger')
            return render_template('import_credentials.html', form=form)
        n = 0
        for item in items:
            cred = Credential(
                title=(item.get('title') or 'Без названия')[:120],
                service_type='other',
                description=item.get('description') or None,
                url=(item.get('url') or '')[:255] or None,
                port=None,
                user_id=current_user.id,
                group_id=None,
            )
            cred.set_credentials(item.get('username') or '', item.get('password') or '')
            db.session.add(cred)
            n += 1
        record_audit(
            current_user.id,
            ACTION_CREDENTIALS_IMPORTED,
            f'Импорт CSV: {n} записей',
            {'count': n, 'format': form.format.data},
        )
        db.session.commit()
        flash(f'Импортировано записей: {n}', 'success')
        return redirect(url_for('credential_bp.list_credentials'))

    return render_template('import_credentials.html', form=form)


@credential_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_credential():
    """Добавление нового учетного данного"""
    form = CredentialForm()
    form.group_id.choices = [(0, 'Без группы')] + [
        (g.id, g.name)
        for g in current_user.groups.order_by(CredentialGroup.position, CredentialGroup.name).all()
    ]

    if form.validate_on_submit():
        credential = Credential(
            title=form.title.data,
            service_type=form.service_type.data,
            description=form.description.data,
            url=form.url.data,
            port=form.port.data,
            user_id=current_user.id,
            group_id=form.group_id.data if form.group_id.data != 0 else None,
        )

        credential.set_credentials(form.username.data, form.password.data)
        credential.apply_extra_data(_extra_from_form(form))

        db.session.add(credential)
        db.session.flush()
        credential.position = credential.id
        record_audit(
            current_user.id,
            ACTION_CREDENTIAL_CREATED,
            f'Создана запись «{credential.title}»',
            {'credential_id': credential.id},
        )
        db.session.commit()

        flash('Учетные данные добавлены!', 'success')
        return redirect(url_for('credential_bp.list_credentials'))

    return render_template('add_credential.html', form=form)


@credential_bp.route('/<int:credential_id>/view')
@login_required
def view_credential(credential_id):
    """Просмотр записи без редактирования (для получателей общего доступа)."""
    credential = Credential.query.get_or_404(credential_id)
    access = _credential_access(current_user, credential)
    if access is None:
        flash('У вас нет доступа к этому ресурсу', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))
    if access == 'owner':
        return redirect(url_for('credential_bp.edit_credential', credential_id=credential_id))

    extra = credential.get_extra_data() or {}
    has_otp = bool((extra.get('otp_secret') or extra.get('otpSecret') or '').strip())
    display_extra = {
        k: v
        for k, v in extra.items()
        if str(k).lower() not in ('otp_secret', 'otpsecret')
    }
    extra_json = (
        json.dumps(display_extra, ensure_ascii=False, indent=2) if display_extra else ''
    )
    return render_template(
        'view_credential.html',
        credential=credential,
        extra_json=extra_json,
        has_otp=has_otp,
    )


@credential_bp.route('/<int:credential_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_credential(credential_id):
    """Редактирование учетного данного"""
    credential = Credential.query.get_or_404(credential_id)
    access = _credential_access(current_user, credential)
    if access is None:
        flash('У вас нет доступа к этому ресурсу', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))
    if access == 'shared':
        return redirect(url_for('credential_bp.view_credential', credential_id=credential_id))

    form = CredentialForm()
    form.group_id.choices = [(0, 'Без группы')] + [
        (g.id, g.name)
        for g in current_user.groups.order_by(CredentialGroup.position, CredentialGroup.name).all()
    ]

    if form.validate_on_submit():
        _append_credential_history(credential, current_user.id)
        credential.title = form.title.data
        credential.service_type = form.service_type.data
        credential.description = form.description.data
        credential.url = form.url.data
        credential.port = form.port.data
        credential.group_id = form.group_id.data if form.group_id.data != 0 else None

        credential.set_credentials(form.username.data, form.password.data)
        credential.apply_extra_data(_extra_from_form(form))

        record_audit(
            current_user.id,
            ACTION_CREDENTIAL_UPDATED,
            f'Обновлена запись «{credential.title}»',
            {'credential_id': credential.id},
        )
        db.session.commit()
        flash('Учетные данные обновлены!', 'success')
        return redirect(url_for('credential_bp.list_credentials'))

    elif request.method == 'GET':
        form.title.data = credential.title
        form.service_type.data = credential.service_type
        form.description.data = credential.description
        form.username.data = credential.get_username()
        form.password.data = credential.get_password()
        form.url.data = credential.url
        form.port.data = credential.port
        form.group_id.data = credential.group_id or 0
        extra = credential.get_extra_data()
        if extra:
            form.extra_data_json.data = json.dumps(extra, ensure_ascii=False, indent=2)

    histories = (
        CredentialHistory.query.filter_by(credential_id=credential.id)
        .order_by(CredentialHistory.created_at.desc())
        .limit(15)
        .all()
    )
    restore_form = RestoreForm()

    return render_template(
        'edit_credential.html',
        form=form,
        credential=credential,
        histories=histories,
        restore_form=restore_form,
    )


@credential_bp.route('/<int:credential_id>/history/<int:history_id>/restore', methods=['POST'])
@login_required
def restore_credential_history(credential_id, history_id):
    credential = Credential.query.get_or_404(credential_id)
    if _credential_access(current_user, credential) != 'owner':
        flash('Нет доступа', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))
    hist = CredentialHistory.query.get_or_404(history_id)
    if hist.credential_id != credential.id:
        flash('Версия не найдена', 'danger')
        return redirect(url_for('credential_bp.edit_credential', credential_id=credential_id))
    mgr = EncryptionManager()
    try:
        snap = json.loads(mgr.decrypt(hist.snapshot_encrypted))
    except Exception:
        flash('Не удалось прочитать сохранённую версию', 'danger')
        return redirect(url_for('credential_bp.edit_credential', credential_id=credential_id))
    _append_credential_history(credential, current_user.id)
    credential.title = snap['title']
    credential.service_type = snap['service_type']
    credential.description = snap['description']
    credential.url = snap.get('url')
    credential.port = snap.get('port')
    credential.group_id = snap.get('group_id')
    credential.set_credentials(snap['username'], snap['password'])
    credential.apply_extra_data(snap.get('extra_data'))
    record_audit(
        current_user.id,
        ACTION_CREDENTIAL_UPDATED,
        f'Восстановлена версия записи «{credential.title}»',
        {'credential_id': credential.id, 'from_history_id': hist.id},
    )
    db.session.commit()
    flash('Версия восстановлена', 'success')
    return redirect(url_for('credential_bp.edit_credential', credential_id=credential_id))


@credential_bp.route('/reorder', methods=['POST'])
@login_required
def reorder_items():
    """Сохранение порядка групп или записей (drag-and-drop)."""
    body = request.get_json(silent=True) or {}
    kind = body.get('kind')
    ids = body.get('ids')
    if not isinstance(ids, list):
        return jsonify({'error': 'bad ids'}), 400
    if kind == 'groups':
        for i, gid in enumerate(ids):
            g = CredentialGroup.query.get(gid)
            if g and g.user_id == current_user.id:
                g.position = i
    elif kind == 'credentials':
        gid = body.get('group_id')
        for i, cid in enumerate(ids):
            c = Credential.query.get(cid)
            if not c or c.user_id != current_user.id:
                continue
            if gid is not None and c.group_id != gid:
                return jsonify({'error': 'group mismatch'}), 400
            c.position = i
    else:
        return jsonify({'error': 'bad kind'}), 400
    db.session.commit()
    return jsonify({'ok': True})


@credential_bp.route('/<int:credential_id>/otp-code')
@login_required
def credential_otp_code(credential_id):
    """Текущий TOTP-код из extra_data.otp_secret (без выдачи секрета)."""
    credential = Credential.query.get_or_404(credential_id)
    if _credential_access(current_user, credential) is None:
        return jsonify({'error': 'forbidden'}), 403
    extra = credential.get_extra_data() or {}
    secret = (extra.get('otp_secret') or extra.get('otpSecret') or '').strip().replace(' ', '')
    if not secret:
        return jsonify({'error': 'no_otp'}), 404
    try:
        totp = pyotp.TOTP(secret)
        code = totp.now()
    except Exception:
        return jsonify({'error': 'bad_secret'}), 400
    now = int(time.time())
    remaining = 30 - (now % 30)
    if remaining == 0:
        remaining = 30
    return jsonify({'code': code, 'period': 30, 'remaining': remaining})


def _ott_redirect(credential_id, form: OneTimeLinkForm):
    nxt = (form.ott_return.data or 'ott').strip().lower()
    if nxt == 'list':
        return redirect(url_for('credential_bp.list_credentials'))
    if nxt == 'edit':
        return redirect(url_for('credential_bp.edit_credential', credential_id=credential_id))
    return redirect(url_for('credential_bp.credential_one_time_link', credential_id=credential_id))


@credential_bp.route('/<int:credential_id>/one-time-link', methods=['GET', 'POST'])
@login_required
def credential_one_time_link(credential_id):
    """Страница одноразовой ссылки; POST — создать и отправить по email или Telegram."""
    credential = Credential.query.get_or_404(credential_id)
    if _credential_access(current_user, credential) != 'owner':
        flash('Только владелец может отправить одноразовую ссылку', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))

    form = OneTimeLinkForm(prefix='ott')
    if request.method == 'GET':
        nxt = (request.args.get('next') or 'ott').strip().lower()
        form.ott_return.data = nxt if nxt in ('list', 'edit', 'ott') else 'ott'
        return render_template('credential_one_time_link.html', credential=credential, form=form)

    if not form.validate_on_submit():
        for errors in form.errors.values():
            for err in errors:
                flash(err, 'danger')
        return render_template('credential_one_time_link.html', credential=credential, form=form)

    method = form.delivery_method.data
    if method == 'email':
        if not mail_configured():
            flash('Почта не настроена (задайте SMTP в разделе «Почта и Telegram» или в окружении).', 'danger')
            return _ott_redirect(credential_id, form)
        recipient = form.recipient_email.data.strip()
    else:
        if not telegram_configured():
            flash('Telegram не настроен (токен в «Почта и Telegram» или TELEGRAM_BOT_TOKEN).', 'danger')
            return _ott_redirect(credential_id, form)
        recipient = form.telegram_chat_id.data.strip()

    raw = secrets.token_urlsafe(32)
    th = _ott_token_hash(raw)
    hours = get_effective_ott_hours()
    expires_at = datetime.utcnow() + timedelta(hours=hours)

    tok = CredentialRevealToken(
        credential_id=credential.id,
        created_by_user_id=current_user.id,
        token_hash=th,
        expires_at=expires_at,
    )
    db.session.add(tok)
    db.session.flush()

    base = get_effective_public_base_url()
    if not base:
        base = request.url_root.rstrip('/')
    link_path = url_for('reveal.reveal_consume', token=raw)
    full_link = f'{base}{link_path}'

    subject = f'SecureVault: одноразовая ссылка — {credential.title}'
    body = (
        f'Запись: {credential.title}\n'
        f'Ссылка действует до {expires_at.strftime("%Y-%m-%d %H:%M")} UTC и сработает один раз.\n\n'
        f'{full_link}\n'
    )

    try:
        if method == 'email':
            send_email(recipient, subject, body)
        else:
            send_telegram_message(recipient, body)
    except Exception as ex:
        db.session.rollback()
        flash(f'Не удалось отправить сообщение: {ex}', 'danger')
        return _ott_redirect(credential_id, form)

    channel = 'email' if method == 'email' else 'telegram'
    record_audit(
        current_user.id,
        ACTION_OTT_SENT,
        f'Отправлена одноразовая ссылка: «{credential.title}», {channel} → {recipient}',
        {
            'credential_id': credential.id,
            'reveal_token_id': tok.id,
            'channel': channel,
            'recipient': recipient,
            'expires_at_utc': expires_at.strftime('%Y-%m-%d %H:%M:%S'),
        },
    )
    db.session.commit()
    flash('Одноразовая ссылка отправлена получателю.', 'success')
    return _ott_redirect(credential_id, form)


@credential_bp.route('/<int:credential_id>/share', methods=['GET', 'POST'])
@login_required
def share_credential(credential_id):
    """Страница общего доступа; POST — выдать доступ по имени пользователя."""
    credential = Credential.query.get_or_404(credential_id)
    if _credential_access(current_user, credential) != 'owner':
        flash('Только владелец может делиться записью', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))

    share_form = ShareCredentialForm(prefix='share')
    share_list = (
        CredentialShare.query.options(joinedload(CredentialShare.shared_with_user))
        .filter_by(credential_id=credential.id)
        .order_by(CredentialShare.created_at.desc())
        .all()
    )

    if request.method == 'GET':
        nxt = (request.args.get('next') or 'share').strip().lower()
        share_form.share_return.data = nxt if nxt in ('list', 'share', 'edit') else 'share'
        return render_template(
            'share_credential.html',
            credential=credential,
            share_form=share_form,
            share_list=share_list,
        )

    if not share_form.validate_on_submit():
        for errors in share_form.errors.values():
            for err in errors:
                flash(err, 'danger')
        return render_template(
            'share_credential.html',
            credential=credential,
            share_form=share_form,
            share_list=share_list,
        )

    username = (share_form.username.data or '').strip()
    target = User.query.filter_by(username=username).first()
    if not target:
        flash('Пользователь с таким именем не найден', 'warning')
    elif target.id == current_user.id:
        flash('Нельзя поделиться записью с самим собой', 'warning')
    elif CredentialShare.query.filter_by(credential_id=credential.id, shared_with_user_id=target.id).first():
        flash('Доступ для этого пользователя уже выдан', 'info')
    else:
        db.session.add(
            CredentialShare(
                credential_id=credential.id,
                shared_with_user_id=target.id,
                shared_by_user_id=current_user.id,
            )
        )
        record_audit(
            current_user.id,
            ACTION_SHARE_GRANTED,
            f'Доступ к «{credential.title}» → «{target.username}»',
            {
                'credential_id': credential.id,
                'shared_with_user_id': target.id,
                'shared_with_username': target.username,
            },
        )
        db.session.commit()
        flash(f'Запись доступна пользователю «{target.username}» (только просмотр и копирование)', 'success')

    return _share_credential_redirect(credential_id, share_form)


def _share_credential_redirect(credential_id, form):
    nxt = (form.share_return.data or 'edit').strip().lower()
    if nxt == 'list':
        return redirect(url_for('credential_bp.list_credentials'))
    if nxt == 'share':
        return redirect(url_for('credential_bp.share_credential', credential_id=credential_id))
    return redirect(url_for('credential_bp.edit_credential', credential_id=credential_id))


@credential_bp.route('/<int:credential_id>/share/<int:share_id>/revoke', methods=['POST'])
@login_required
def revoke_credential_share(credential_id, share_id):
    """Отозвать доступ к записи."""
    credential = Credential.query.get_or_404(credential_id)
    if _credential_access(current_user, credential) != 'owner':
        flash('Только владелец может отзывать доступ', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))

    share = CredentialShare.query.filter_by(id=share_id, credential_id=credential.id).first_or_404()
    username = share.shared_with_user.username if share.shared_with_user else str(share.shared_with_user_id)
    shared_uid = share.shared_with_user_id
    record_audit(
        current_user.id,
        ACTION_SHARE_REVOKED,
        f'Отозван доступ к «{credential.title}» у «{username}»',
        {
            'credential_id': credential.id,
            'shared_with_user_id': shared_uid,
            'share_id': share_id,
        },
    )
    db.session.delete(share)
    db.session.commit()
    flash(f'Доступ для «{username}» отозван', 'info')
    return redirect(url_for('credential_bp.share_credential', credential_id=credential_id))


@credential_bp.route('/<int:credential_id>/delete', methods=['POST'])
@login_required
def delete_credential(credential_id):
    """Удаление учетного данного"""
    credential = Credential.query.get_or_404(credential_id)

    if _credential_access(current_user, credential) != 'owner':
        return jsonify({'error': 'Unauthorized'}), 403

    title = credential.title
    cid = credential.id
    db.session.delete(credential)
    record_audit(
        current_user.id,
        ACTION_CREDENTIAL_DELETED,
        f'Удалена запись «{title}»',
        {'credential_id': cid},
    )
    db.session.commit()

    flash('Учетные данные удалены!', 'success')
    return redirect(url_for('credential_bp.list_credentials'))


def _credential_copy_field_response(credential_id, field):
    """field: 'password' | 'username'"""
    credential = Credential.query.get_or_404(credential_id)

    if _credential_access(current_user, credential) not in ('owner', 'shared'):
        return jsonify({'error': 'Unauthorized'}), 403

    credential.last_accessed = datetime.utcnow()
    record_audit(
        current_user.id,
        ACTION_CREDENTIAL_FIELD_COPIED,
        f'Скопировано: {field} — «{credential.title}»',
        {'credential_id': credential.id, 'field': field},
    )
    db.session.commit()

    if field == 'password':
        return jsonify({'password': credential.get_password()})
    return jsonify({'username': credential.get_username()})


@credential_bp.route('/<int:credential_id>/copy-field', methods=['POST'])
@login_required
def copy_credential_field(credential_id):
    """Копирование логина или пароля с записью в аудит."""
    payload = request.get_json(silent=True) or {}
    field = (payload.get('field') or '').strip().lower()
    if field not in ('password', 'username'):
        return jsonify({'error': 'field must be "password" or "username"'}), 400
    return _credential_copy_field_response(credential_id, field)


@credential_bp.route('/<int:credential_id>/copy-password', methods=['POST'])
@login_required
def copy_password(credential_id):
    """Обратная совместимость."""
    return _credential_copy_field_response(credential_id, 'password')


@credential_bp.route('/<int:credential_id>/copy-username', methods=['POST'])
@login_required
def copy_username(credential_id):
    """Обратная совместимость."""
    return _credential_copy_field_response(credential_id, 'username')


# ===== Управление группами =====
@credential_bp.route('/group/add', methods=['GET', 'POST'])
@login_required
def add_group():
    """Добавление группы"""
    form = GroupForm()
    if form.validate_on_submit():
        group = CredentialGroup(
            name=form.name.data,
            description=form.description.data,
            color=form.color.data or '#6366f1',
            user_id=current_user.id,
        )
        db.session.add(group)
        db.session.flush()
        mx = (
            db.session.query(func.max(CredentialGroup.position))
            .filter_by(user_id=current_user.id)
            .scalar()
        )
        group.position = (mx or 0) + 1
        record_audit(
            current_user.id,
            ACTION_GROUP_CREATED,
            f'Создана группа «{group.name}»',
            {'group_id': group.id},
        )
        db.session.commit()

        flash('Группа создана!', 'success')
        return redirect(url_for('credential_bp.list_credentials'))

    return render_template('group_form.html', form=form)


@credential_bp.route('/group/<int:group_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_group(group_id):
    """Редактирование группы"""
    group = CredentialGroup.query.get_or_404(group_id)
    if group.user_id != current_user.id:
        flash('У вас нет доступа', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))

    form = GroupForm()
    if form.validate_on_submit():
        group.name = form.name.data
        group.description = form.description.data
        group.color = form.color.data or '#6366f1'
        record_audit(
            current_user.id,
            ACTION_GROUP_UPDATED,
            f'Обновлена группа «{group.name}»',
            {'group_id': group.id},
        )
        db.session.commit()
        flash('Группа обновлена!', 'success')
        return redirect(url_for('credential_bp.list_credentials'))

    if request.method == 'GET':
        form.name.data = group.name
        form.description.data = group.description
        form.color.data = group.color or '#6366f1'

    return render_template('edit_group.html', form=form, group=group)


@credential_bp.route('/group/<int:group_id>/delete', methods=['POST'])
@login_required
def delete_group(group_id):
    """Удаление группы"""
    group = CredentialGroup.query.get_or_404(group_id)

    if group.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    gname = group.name
    gid = group.id
    db.session.delete(group)
    record_audit(
        current_user.id,
        ACTION_GROUP_DELETED,
        f'Удалена группа «{gname}»',
        {'group_id': gid},
    )
    db.session.commit()

    flash('Группа удалена! Связанные учётные записи также удалены (каскад).', 'warning')
    return redirect(url_for('credential_bp.list_credentials'))
