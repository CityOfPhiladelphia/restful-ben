from functools import wraps
import binascii
import os
import uuid
import json
from datetime import datetime, timedelta

from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.ext.declarative import declared_attr
from flask import request, current_app
from flask_restful import Resource, abort
from passlib.hash import argon2
from marshmallow import Schema, fields
from flask_login import LoginManager, login_required, current_user
from cryptography.fernet import Fernet
import dateutil.parser

def authorization(roles_permissions):
    def authorization_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if hasattr(current_user, 'role'):
                role = current_user.role
            else:
                role = None

            if role and role in roles_permissions:
                if request.method in roles_permissions[role]:
                    return func(*args, **kwargs)

            abort(403)
        return wrapper
    return authorization_decorator

def csrf_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if request.method in ['GET','HEAD','OPTIONS'] or \
            (hasattr(current_user, 'is_api') and current_user.is_api):
            return func(*args, **kwargs)

        ## check for X-CSRF header and check signature
        try:
            csrf = current_app.auth.csrf
            csrf.fernet.decrypt(request.headers[csrf.header].encode('utf-8'))
        except:
            abort(401)

        return func(*args, **kwargs)
    return wrapper

class CSRF(object):
    def __init__(self, csrf_secret=None, csrf_header=None):
        csrf_secret = csrf_secret or os.getenv('CSRF_SECRET', None)
        if csrf_secret == None:
            raise Exception('`csrf_secret` required')
        self.fernet = Fernet(csrf_secret)
        self.header = csrf_header or 'X-CSRF'

    def generate_token(self):
        return self.fernet.encrypt(os.urandom(32)).decode('utf-8')

class TokenMixin(object):
    """
    Mix with a model base class
    """

    __tablename__ = 'tokens'

    # instance of cryptography.fernet.Fernet
    fernet = None

    ## TODO: scopes?

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ## TODO: type ? like session, token, refresh_token
    @declared_attr
    def user_id(cls):
        return Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, index=True)
    ip = Column(INET, nullable=False)
    user_agent = Column(String)
    created_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now())
    updated_at = Column(DateTime,
                        nullable=False,
                        server_default=func.now(),
                        onupdate=func.now())

    @property
    def token(self):
        ## TODO: include all or part of the id outside the token? security issue?
        return self.fernet.encrypt(json.dumps({
            'id': str(self.id),
            'user_id': self.user_id,
            'expires_at': self.expires_at.isoformat()
        }).encode('utf-8')).decode('utf-8')

    @classmethod
    def verify_token(cls, session, input_token):
        try:
            data = json.loads(cls.fernet.decrypt(input_token.encode('utf-8')).decode('utf-8'))
            expires_at = dateutil.parser.parse(data['expires_at'])
        except:
            return None

        if expires_at <= datetime.utcnow():
            return None

        token = session.query(cls) \
            .filter(cls.id == data['id'],
                    cls.user_id == data['user_id'],
                    cls.revoked_at == None,
                    cls.expires_at > func.now()) \
            .one_or_none()

        if token:
            return token

        return None

class UserAuthMixin(object):
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String)

    @property
    def password(self):
        raise Exception('Cannot get password from User.')

    def get_password_hash(self, password):
        return argon2.using(rounds=4).hash(password)

    @password.setter
    def password(self, password):
        if password is None:
            self.hashed_password = None
        else:
            self.hashed_password = self.get_password_hash(password)

    def verify_password(self, input_password):
        if not self.hashed_password or not input_password:
            return False

        return argon2.verify(input_password, self.hashed_password)

class SessionSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

session_schema = SessionSchema()

def get_ip(number_of_proxies):
    if 'X-Forwarded-For' in request.headers:
        path = request.headers.getlist("X-Forwarded-For")[0].rpartition(' ')
        if len(path) != number_of_proxies:
            abort(401)
        return path[-1]
    if number_of_proxies > 0:
        abort(401)
    return request.remote_addr

class SessionResource(Resource):
    token_model = None
    cookie_name = 'session'
    cookie_domain = None
    cookie_path = None
    secure_cookie = False
    session_timeout = timedelta(hours=12)
    number_of_proxies = 0

    def get_cookie(self, token, expires_at):
        domain = ''
        if self.cookie_domain:
            domain = 'Domain={}; '.format(self.domain)

        path = ''
        if self.cookie_path:
            path = 'Path={}; '.format(self.path)

        secure = ''
        if self.secure_cookie:
            secure = 'Secure; '

        return '{}={}; Expires={}; {}{}{}HttpOnly'.format(
            self.cookie_name,
            token,
            expires_at,
            domain,
            path,
            secure)

    def session_cookie(self, user):
        token = self.token_model(
            user_id=user.id,
            expires_at=datetime.utcnow() + self.session_timeout,
            ip=get_ip(self.number_of_proxies),
            user_agent=request.user_agent.string)
        self.session.add(token)
        self.session.commit()

        expires_at = token.expires_at.strftime('%a, %d %b %Y %H:%M:%S GMT')

        return self.get_cookie(token.token, expires_at)

    def post(self):
        raw_body = request.json
        session_load = session_schema.load(raw_body or {})

        if session_load.errors:
            abort(400, errors=session_load.errors)

        session = session_load.data

        user = self.session.query(self.User)\
                    .filter(self.User.username == session['username'])\
                    .first()

        if not user:
            abort(401, errors=['Not Authorized'])

        password_matches = user.verify_password(session['password'])
        if not password_matches:
            abort(401, errors=['Not Authorized'])

        cookie = self.session_cookie(user)

        response_body = {'csrf_token': self.csrf.generate_token()}

        return response_body, 201, {'Set-Cookie': cookie}

    @login_required
    def get(self):
        return None, 204

    @login_required
    def delete(self):
        token = current_user.token
        token.revoked_at = datetime.utcnow()
        self.session.commit()

        cookie = self.get_cookie('deleted', 'Thu, 01 Jan 1970 00:00:00 GMT')

        return None, 204, {'Set-Cookie': cookie}

## TODO: make this more abstract? allow for remote token and users? eg auth service client. maybe two classes

class Auth(object):
    def __init__(self,
                 app=None,
                 session=None,
                 csrf_header=None,
                 csrf_secret=None,
                 base_model=None,
                 user_model=None,
                 token_model=None,
                 token_secret=None,
                 session_resource=None,
                 cookie_name='session',
                 cookie_domain=None,
                 cookie_path=None,
                 secure_cookie=False,
                 session_timeout=timedelta(hours=12),
                 number_of_proxies=0):
        self.user_model = user_model
        self.session = session

        self.cookie_name = cookie_name

        self.login_manager = LoginManager()
        self.login_manager.request_loader(self.load_user_from_request)

        if app:
            self.init_app(app)

        self.csrf = CSRF(csrf_secret=csrf_secret, csrf_header=csrf_header)

        if base_model and not token_model:
            token_secret = token_secret or os.getenv('TOKEN_SECRET', None)
            if not token_secret:
                raise Exception('`token_secret` required if `token_model` is not passed')

            Token = type('Token', (TokenMixin, base_model,), {
                'fernet': Fernet(token_secret)
            })

            self.token_model = Token
        else:
            self.token_model = token_model

        if session_resource:
            self.session_resource = session_resource
        else:
            LocalSessionResource = type('LocalSessionResource', (SessionResource,), {
                'User': self.user_model,
                'token_model': self.token_model,
                'session': self.session,
                'csrf': self.csrf,
                'cookie_name': self.cookie_name,
                'cookie_domain': cookie_domain,
                'cookie_path': cookie_path,
                'secure_cookie': secure_cookie,
                'session_timeout': session_timeout,
                'number_of_proxies': number_of_proxies
            })

            self.session_resource = LocalSessionResource

    def init_app(self, app):
        self.login_manager.init_app(app)
        setattr(app, 'auth', self)

    def load_user_from_request(self, request):
        token = None

        authorization_header = request.headers.get('Authorization')
        if authorization_header:
            token = authorization_header.replace('Bearer ', '', 1)
        elif self.cookie_name in request.cookies:
            token = request.cookies[self.cookie_name]

        token = self.token_model.verify_token(self.session, token)

        if token == None:
            return None

        user = self.session.query(self.user_model).get(token.user_id)

        if user == None:
            return None

        setattr(user, 'token', token)

        return user
