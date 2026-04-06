import json
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, IntegerField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from app.models import User


class RegistrationForm(FlaskForm):
    """Форма регистрации"""
    username = StringField('Имя пользователя', validators=[
        DataRequired(),
        Length(min=3, max=80, message='Имя должно быть от 3 до 80 символов')
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[
        DataRequired(),
        Length(min=8, message='Пароль должен быть не менее 8 символов')
    ])
    confirm_password = PasswordField('Подтверждение пароля', validators=[
        DataRequired(),
        EqualTo('password', message='Пароли не совпадают')
    ])
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Это имя уже занято')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Этот email уже зарегистрирован')


class LoginForm(FlaskForm):
    """Форма входа"""
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class CredentialForm(FlaskForm):
    """Форма для добавления/редактирования учетных данных"""
    title = StringField('Название', validators=[DataRequired(), Length(min=1, max=120)])
    service_type = SelectField('Тип сервиса', choices=[
        ('server', 'Сервер'),
        ('database', 'База данных'),
        ('app', 'Приложение'),
        ('email', 'Email'),
        ('cloud', 'Облачное хранилище'),
        ('vpn', 'VPN'),
        ('other', 'Другое')
    ])
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    url = StringField('URL/Адрес', validators=[Optional()])
    port = IntegerField('Порт', validators=[Optional()])
    description = TextAreaField('Описание', validators=[Optional()])
    group_id = SelectField('Группа', coerce=int, validators=[Optional()])
    extra_data_json = TextAreaField('Дополнительные данные (JSON)', validators=[Optional()])
    submit = SubmitField('Сохранить')

    def validate_extra_data_json(self, field):
        if not field.data or not str(field.data).strip():
            return
        try:
            val = json.loads(field.data)
            if not isinstance(val, dict):
                raise ValidationError('Ожидается JSON-объект, например {"ключ": "значение"}')
        except json.JSONDecodeError:
            raise ValidationError('Некорректный JSON')


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
