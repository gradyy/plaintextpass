from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy import MetaData

convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention = convention)

db = SQLAlchemy(metadata = metadata)

column_length = {
    "user_id": 200,
    "username": 100,
    "display_name": 100,
    "email": 100,
    "pub_key": 255, #length 65 is not sufficient
    "credential_id": 255,
    "rp_id": 255,
    "icon_url": 2000,
    "domain": 255,
    "password": 100
}

class WebAuthnUserAccount(db.Model, UserMixin):

    __tablename__ = 'webauthn_users'

    user_id = db.Column(db.String(column_length["user_id"]), primary_key = True)

    username = db.Column(db.String(column_length["username"]), unique = True, nullable = False)
    display_name = db.Column(db.String(column_length["display_name"]), unique = False, nullable = False)
    email = db.Column(db.String(column_length["email"]), unique = False, nullable = False)
    pub_key = db.Column(db.String(column_length["pub_key"]), unique = True, nullable = True)
    credential_id = db.Column(db.String(column_length["credential_id"]), unique = True, nullable = False)
    sign_count = db.Column(db.Integer, default = 0)
    rp_id = db.Column(db.String(column_length["rp_id"]), unique = False, nullable = False)
    icon_url = db.Column(db.String(column_length["icon_url"]), unique = False, nullable = False)

    password = db.Column(db.String(column_length["password"]), unique = False, nullable = True)

    activated = db.Column(db.Boolean, unique = False, nullable = False, default = True)

    @property
    def is_active(self):
        #equality comparison required to guarantee boolean return type
        return self.activated == True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.user_id

class Password(db.Model):
    __tablename__ = 'passwords'

    user_id = db.Column(
        db.String(column_length["user_id"]),
        db.ForeignKey('webauthn_users.user_id'),
        primary_key = True
    )
    password_id = db.Column(db.Integer, primary_key = True)
    domain = db.Column(db.String(column_length["domain"]), unique = False, nullable = True)
    username = db.Column(db.String(column_length["username"]), unique = False, nullable = False)
    password = db.Column(db.String(column_length["password"]), unique = False, nullable = True)
