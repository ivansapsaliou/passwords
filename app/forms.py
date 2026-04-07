import json
import ipaddress
from urllib.parse import urlparse
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import (
    StringField,
    PasswordField,
    TextAreaField,
    SelectField,
    IntegerField,
    SubmitField,
    HiddenField,
    RadioField,
    BooleanField,
    FieldList,
    FormField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional, NumberRange
from wtforms.widgets import HiddenInput
from app.models import User, Server


class LoginForm(FlaskForm):
    """Форма входа"""
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class TotpLoginForm(FlaskForm):
    """Второй шаг входа — код TOTP."""
    code = StringField('Код аутентификатора', validators=[DataRequired(), Length(min=6, max=8)])
    submit = SubmitField('Подтвердить')

    def validate_code(self, field):
        s = (field.data or '').replace(' ', '').strip()
        if not s.isdigit():
            raise ValidationError('Код должен содержать только цифры')
        if len(s) != 6:
            raise ValidationError('Введите 6-значный код')
        field.data = s


class TotpSetupForm(FlaskForm):
    """Подтверждение привязки TOTP."""
    code = StringField('Код из приложения', validators=[DataRequired(), Length(min=6, max=8)])
    submit = SubmitField('Включить 2FA')

    def validate_code(self, field):
        s = (field.data or '').replace(' ', '').strip()
        if not s.isdigit() or len(s) != 6:
            raise ValidationError('Введите 6-значный код')
        field.data = s


class TotpDisableForm(FlaskForm):
    """Отключение 2FA."""
    password = PasswordField('Текущий пароль', validators=[DataRequired()])
    code = StringField('Код из приложения-аутентификатора', validators=[DataRequired(), Length(min=6, max=8)])
    submit = SubmitField('Отключить 2FA')

    def validate_code(self, field):
        s = (field.data or '').replace(' ', '').strip()
        if not s.isdigit() or len(s) != 6:
            raise ValidationError('Введите 6-значный код')
        field.data = s


SERVICE_TYPE_CHOICES = [
    ('server', 'Сервер'),
    ('database', 'База данных'),
    ('app', 'Приложение'),
    ('email', 'Email'),
    ('cloud', 'Облачное хранилище'),
    ('vpn', 'VPN'),
    ('other', 'Другое'),
]


def _validate_ip_address_field(field):
    if not field.data or not str(field.data).strip():
        return
    raw = str(field.data).strip()
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        raise ValidationError('Укажите корректный IPv4 или IPv6')
    field.data = raw


class CredentialForm(FlaskForm):
    """Форма для добавления/редактирования учетных данных"""
    title = StringField('Название', validators=[DataRequired(), Length(min=1, max=120)])
    service_type = SelectField('Тип сервиса', choices=SERVICE_TYPE_CHOICES)
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[Optional()])
    url = StringField('URL/Адрес', validators=[Optional()])
    port = IntegerField('Порт', validators=[Optional(), NumberRange(min=1, max=65535, message='Порт от 1 до 65535')])
    description = TextAreaField('Описание', validators=[Optional()])
    group_id = SelectField('Группа', coerce=int, validators=[Optional()])
    server_id = SelectField('Сервер', coerce=int, validators=[Optional()])
    extra_data_json = TextAreaField('Дополнительные данные (JSON)', validators=[Optional()])
    submit = SubmitField('Сохранить')

    def __init__(self, require_password=True, user_id=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._require_password = require_password
        self._user_id_for_server = user_id

    def validate_password(self, field):
        if self._require_password and not (field.data or '').strip():
            raise ValidationError('Укажите пароль')

    def validate_server_id(self, field):
        if not self._user_id_for_server or not field.data or field.data == 0:
            return
        row = Server.query.filter_by(id=field.data, user_id=self._user_id_for_server).first()
        if not row:
            raise ValidationError('Указанный сервер не найден')

    def validate_url(self, field):
        if not field.data or not str(field.data).strip():
            return
        raw = field.data.strip()
        candidate = raw if '://' in raw else f'https://{raw}'
        p = urlparse(candidate)
        if p.scheme not in ('http', 'https'):
            raise ValidationError('Разрешены только URL с протоколом http или https')
        if not p.netloc:
            raise ValidationError('Укажите корректный адрес (например https://example.com или example.com)')

    def validate_extra_data_json(self, field):
        if not field.data or not str(field.data).strip():
            return
        try:
            val = json.loads(field.data)
            if not isinstance(val, dict):
                raise ValidationError('Ожидается JSON-объект, например {"ключ": "значение"}')
        except json.JSONDecodeError:
            raise ValidationError('Некорректный JSON')


class CredentialInlineRowForm(FlaskForm):
    """Строка учётки внутри формы «сервер + пакет» (без собственного CSRF)."""

    class Meta:
        csrf = False

    credential_id = IntegerField(
        'ID записи',
        default=0,
        widget=HiddenInput(),
        validators=[Optional(), NumberRange(min=0)],
    )
    title = StringField('Название', validators=[Optional(), Length(max=120)])
    username = StringField('Логин', validators=[Optional(), Length(max=255)])
    password = PasswordField('Пароль', validators=[Optional()])
    description = StringField('Описание', validators=[Optional(), Length(max=4000)])
    service_type = SelectField('Тип', choices=SERVICE_TYPE_CHOICES, default='server')
    group_id = SelectField('Группа', coerce=int, validators=[Optional()])


class ServerForm(FlaskForm):
    """Редактирование сервера (имя и IP)."""
    name = StringField('Название', validators=[DataRequired(), Length(min=1, max=120)])
    ip_address = StringField('IP-адрес', validators=[DataRequired(), Length(max=45)])
    submit = SubmitField('Сохранить')

    def validate_ip_address(self, field):
        _validate_ip_address_field(field)


class ServerWithCredentialsForm(FlaskForm):
    """Создание сервера и нескольких учётных записей за один раз."""
    name = StringField('Название сервера', validators=[DataRequired(), Length(min=1, max=120)])
    ip_address = StringField('IP-адрес', validators=[DataRequired(), Length(max=45)])
    server_description = TextAreaField('Описание хоста', validators=[Optional(), Length(max=12000)])
    credentials = FieldList(FormField(CredentialInlineRowForm), min_entries=0, max_entries=200)
    submit = SubmitField('Сохранить сервер и учётки')

    def __init__(self, edit_mode=False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._edit_mode = edit_mode

    def validate_ip_address(self, field):
        _validate_ip_address_field(field)

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators=extra_validators):
            return False
        ok = True
        for entry in self.credentials.entries:
            sub = entry.form
            t = (sub.title.data or '').strip()
            u = (sub.username.data or '').strip()
            p = (sub.password.data or '').strip()
            d = (sub.description.data or '').strip()
            try:
                cid = int(sub.credential_id.data or 0)
            except (TypeError, ValueError):
                cid = 0

            if self._edit_mode and cid:
                if not t and not u and not p and not d:
                    continue
                if not t or not u:
                    err = 'Укажите название и логин или удалите строку'
                    sub.title.errors.append(err)
                    ok = False
                continue

            if not t and not u and not p and not d:
                continue
            if not (t and u and p):
                err = 'Укажите название, логин и пароль полностью или очистите строку'
                sub.title.errors.append(err)
                ok = False
        return ok


class RestoreForm(FlaskForm):
    """Только CSRF для POST без полей."""
    pass


class ImportCsvForm(FlaskForm):
    """Импорт учётных записей из CSV."""
    format = SelectField(
        'Формат экспорта',
        choices=[
            ('bitwarden', 'Bitwarden'),
            ('chrome', 'Google Chrome'),
            ('keepass', 'KeePass / универсальный'),
        ],
        validators=[DataRequired()],
    )
    file = FileField(
        'Файл .csv',
        validators=[
            FileRequired(message='Выберите файл'),
            FileAllowed(['csv'], message='Разрешены только файлы .csv'),
        ],
    )
    submit = SubmitField('Импортировать')


class GroupForm(FlaskForm):
    """Форма для группы учетных данных"""
    name = StringField('Название группы', validators=[DataRequired(), Length(min=1, max=120)])
    description = TextAreaField('Описание', validators=[Optional()])
    color = StringField(
        'Цвет',
        default='#6366f1',
        validators=[Optional()],
        render_kw={'type': 'color', 'class': 'form-control form-control-color'},
    )
    submit = SubmitField('Создать группу')


class ShareCredentialForm(FlaskForm):
    """Выдача доступа к записи другому пользователю по имени (логину)."""
    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=3, max=80, message='Укажите имя пользователя (3–80 символов)'),
    ])
    share_return = HiddenField(default='edit', validators=[Optional()])
    submit_share = SubmitField('Поделиться')


class AdminDeliverySettingsForm(FlaskForm):
    """Настройки SMTP, Telegram и публичного URL (сохранение в БД перекрывает env)."""
    mail_server = StringField('SMTP-сервер', validators=[Optional(), Length(max=255)])
    mail_port = IntegerField('Порт', validators=[Optional()])
    mail_tls_mode = SelectField(
        'STARTTLS',
        choices=[
            ('env', 'Как в окружении'),
            ('yes', 'Включить'),
            ('no', 'Выключить'),
        ],
        validators=[DataRequired()],
    )
    mail_username = StringField('Имя пользователя SMTP', validators=[Optional(), Length(max=255)])
    mail_default_sender = StringField('Адрес отправителя', validators=[Optional(), Length(max=255)])
    mail_password_new = PasswordField(
        'Пароль SMTP (оставьте пустым, чтобы не менять)',
        validators=[Optional()],
    )
    telegram_bot_token_new = PasswordField(
        'Токен бота Telegram (оставьте пустым, чтобы не менять)',
        validators=[Optional()],
    )
    public_base_url = StringField(
        'Публичный базовый URL',
        validators=[Optional(), Length(max=512)],
        render_kw={'placeholder': 'https://vault.example.com'},
    )
    ott_link_expires_hours = IntegerField(
        'Срок жизни одноразовой ссылки (часы)',
        validators=[Optional(), NumberRange(min=1, max=8760)],
    )
    submit = SubmitField('Сохранить настройки')


class ChangePasswordForm(FlaskForm):
    """Смена пароля аккаунта"""
    current_password = PasswordField('Текущий пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль', validators=[
        DataRequired(),
        Length(min=8, message='Пароль должен быть не менее 8 символов'),
    ])
    confirm_password = PasswordField('Подтверждение', validators=[
        DataRequired(),
        EqualTo('new_password', message='Пароли не совпадают'),
    ])
    submit = SubmitField('Обновить пароль')


class AdminCreateUserForm(FlaskForm):
    """Создание пользователя администратором"""
    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=3, max=80, message='Имя должно быть от 3 до 80 символов'),
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    grant_admin = BooleanField('Права администратора', default=False)
    submit = SubmitField('Создать пользователя')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Это имя уже занято')



class AccountOnboardingForm(FlaskForm):
    """Первичная установка пароля через ссылку-приглашение."""
    new_password = PasswordField('Новый пароль', validators=[
        DataRequired(),
        Length(min=8, message='Пароль должен быть не менее 8 символов'),
    ])
    confirm_password = PasswordField('Подтверждение пароля', validators=[
        DataRequired(),
        EqualTo('new_password', message='Пароли не совпадают'),
    ])
    submit = SubmitField('Сохранить пароль и продолжить')


class AdminEditUserForm(FlaskForm):
    """Редактирование пользователя администратором"""

    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=3, max=80, message='Имя должно быть от 3 до 80 символов'),
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    is_active = BooleanField('Учётная запись активна', default=True)
    grant_admin = BooleanField('Права администратора', default=False)
    new_password = PasswordField('Новый пароль (оставьте пустым, чтобы не менять)', validators=[
        Optional(),
        Length(min=8, message='Пароль не короче 8 символов'),
    ])
    confirm_password = PasswordField('Подтверждение нового пароля', validators=[Optional()])
    submit = SubmitField('Сохранить')

    def __init__(self, user_id=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._user_id = user_id

    def validate_username(self, field):
        q = User.query.filter(User.username == field.data)
        if self._user_id is not None:
            q = q.filter(User.id != self._user_id)
        if q.first():
            raise ValidationError('Это имя уже занято')

    def validate_new_password(self, field):
        """Обрезка пробелов; EqualTo нельзя — в WTForms 3 он срабатывает до Form.validate()."""
        if field.data is not None:
            field.data = field.data.strip()

    def validate_confirm_password(self, field):
        new_p = (self.new_password.data or '').strip()
        conf = (field.data or '').strip()
        field.data = conf
        if not new_p:
            return
        if conf != new_p:
            raise ValidationError('Пароли не совпадают')

class OneTimeLinkForm(FlaskForm):
    """Отправка одноразовой ссылки на показ учётных данных."""
    delivery_method = RadioField(
        'Способ доставки',
        choices=[('email', 'Email'), ('telegram', 'Telegram')],
        validators=[DataRequired()],
        default='email',
    )
    recipient_email = StringField('Email получателя', validators=[Optional(), Email()])
    telegram_chat_id = StringField('Telegram chat_id', validators=[Optional(), Length(max=32)])
    ott_return = HiddenField(default='ott', validators=[Optional()])
    submit_ott = SubmitField('Отправить ссылку')

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators=extra_validators):
            return False
        if self.delivery_method.data == 'email':
            if not (self.recipient_email.data or '').strip():
                self.recipient_email.errors.append('Укажите email получателя')
                return False
        elif self.delivery_method.data == 'telegram':
            tid = (self.telegram_chat_id.data or '').strip()
            if not tid:
                self.telegram_chat_id.errors.append('Укажите числовой chat_id получателя')
                return False
            if not tid.lstrip('-').isdigit():
                self.telegram_chat_id.errors.append(
                    'chat_id должен быть числом (узнайте у @userinfobot или через getUpdates)'
                )
                return False
        return True
