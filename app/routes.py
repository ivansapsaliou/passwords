import hashlib
import json
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy import or_, nulls_last, update
from sqlalchemy.orm import joinedload

from app import db
from app.models import (
    User,
    Credential,
    CredentialGroup,
    CredentialShare,
    CredentialRevealToken,
    DeliverySettings,
    AuditLog,
)
from app.forms import (
    LoginForm,
    CredentialForm,
    GroupForm,
    ShareCredentialForm,
    ChangePasswordForm,
    AdminCreateUserForm,
    AdminEditUserForm,
    OneTimeLinkForm,
    AdminDeliverySettingsForm,
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
    ACTION_LABELS,
    ALL_ACTIONS,
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
main_bp = Blueprint('main', __name__)
credential_bp = Blueprint('credential_bp', __name__, url_prefix='/credentials')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
reveal_bp = Blueprint('reveal', __name__)


def _ott_token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


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
def login():
    """Вход пользователя"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)
            user.last_login = datetime.utcnow()
            record_audit(user.id, ACTION_LOGIN, f'Вход: {user.username}')
            db.session.commit()

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.dashboard'))
        else:
            flash('Неверное имя или пароль', 'danger')

    return render_template('login.html', form=form)


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
    groups = current_user.groups.all()
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
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()
        record_audit(
            current_user.id,
            ACTION_USER_CREATED,
            f'Создан пользователь «{user.username}»',
            {
                'new_user_id': user.id,
                'email': user.email,
                'is_admin': user.is_admin,
            },
        )
        db.session.commit()
        flash(f'Пользователь «{user.username}» создан.', 'success')
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

    credentials = query.order_by(Credential.updated_at.desc()).paginate(page=page, per_page=10)
    groups = current_user.groups.order_by(CredentialGroup.name).all()
    groups_meta = [{'group': g, 'count': g.credentials.count()} for g in groups]

    return render_template(
        'credentials.html',
        credentials=credentials,
        groups=groups,
        groups_meta=groups_meta,
        search=search,
        group_id=group_id,
    )


@credential_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_credential():
    """Добавление нового учетного данного"""
    form = CredentialForm()
    form.group_id.choices = [(0, 'Без группы')] + [
        (g.id, g.name) for g in current_user.groups.all()
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

    extra = credential.get_extra_data()
    extra_json = json.dumps(extra, ensure_ascii=False, indent=2) if extra else ''
    return render_template(
        'view_credential.html',
        credential=credential,
        extra_json=extra_json,
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
        (g.id, g.name) for g in current_user.groups.all()
    ]

    if form.validate_on_submit():
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

    return render_template(
        'edit_credential.html',
        form=form,
        credential=credential,
    )


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


@credential_bp.route('/<int:credential_id>/copy-password', methods=['POST'])
@login_required
def copy_password(credential_id):
    """Копирование пароля (безопасно)"""
    credential = Credential.query.get_or_404(credential_id)

    if _credential_access(current_user, credential) not in ('owner', 'shared'):
        return jsonify({'error': 'Unauthorized'}), 403

    credential.last_accessed = datetime.utcnow()
    db.session.commit()

    password = credential.get_password()
    return jsonify({'password': password})


@credential_bp.route('/<int:credential_id>/copy-username', methods=['POST'])
@login_required
def copy_username(credential_id):
    """Копирование логина"""
    credential = Credential.query.get_or_404(credential_id)

    if _credential_access(current_user, credential) not in ('owner', 'shared'):
        return jsonify({'error': 'Unauthorized'}), 403

    credential.last_accessed = datetime.utcnow()
    db.session.commit()

    return jsonify({'username': credential.get_username()})


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
