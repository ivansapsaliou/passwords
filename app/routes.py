import json
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, Credential, CredentialGroup
from app.forms import (
    RegistrationForm,
    LoginForm,
    CredentialForm,
    GroupForm,
    ChangePasswordForm,
)
from datetime import datetime

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
main_bp = Blueprint('main', __name__)
credential_bp = Blueprint('credential_bp', __name__, url_prefix='/credentials')


def _extra_from_form(form):
    if not form.extra_data_json.data or not str(form.extra_data_json.data).strip():
        return None
    return json.loads(form.extra_data_json.data)


# ===== Аутентификация =====
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Регистрация пользователя"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash('Аккаунт создан! Можете войти.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html', form=form)


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
    total_credentials = current_user.credentials.count()
    total_groups = len(groups)

    recent_credentials = current_user.credentials.order_by(
        Credential.last_accessed.desc()
    ).limit(5).all()

    service_types = {}
    for cred in current_user.credentials.all():
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
@credential_bp.route('/')
@login_required
def list_credentials():
    """Список всех учетных данных"""
    page = request.args.get('page', 1, type=int)
    group_id = request.args.get('group_id', None, type=int)
    search = request.args.get('search', '')

    query = current_user.credentials

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
        db.session.commit()

        flash('Учетные данные добавлены!', 'success')
        return redirect(url_for('credential_bp.list_credentials'))

    return render_template('add_credential.html', form=form)


@credential_bp.route('/<int:credential_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_credential(credential_id):
    """Редактирование учетного данного"""
    credential = Credential.query.get_or_404(credential_id)

    if credential.user_id != current_user.id:
        flash('У вас нет доступа к этому ресурсу', 'danger')
        return redirect(url_for('credential_bp.list_credentials'))

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

    return render_template('edit_credential.html', form=form, credential=credential)


@credential_bp.route('/<int:credential_id>/delete', methods=['POST'])
@login_required
def delete_credential(credential_id):
    """Удаление учетного данного"""
    credential = Credential.query.get_or_404(credential_id)

    if credential.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(credential)
    db.session.commit()

    flash('Учетные данные удалены!', 'success')
    return redirect(url_for('credential_bp.list_credentials'))


@credential_bp.route('/<int:credential_id>/copy-password', methods=['POST'])
@login_required
def copy_password(credential_id):
    """Копирование пароля (безопасно)"""
    credential = Credential.query.get_or_404(credential_id)

    if credential.user_id != current_user.id:
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

    if credential.user_id != current_user.id:
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

    db.session.delete(group)
    db.session.commit()

    flash('Группа удалена! Связанные учётные записи также удалены (каскад).', 'warning')
    return redirect(url_for('credential_bp.list_credentials'))
