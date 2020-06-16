from flask_sqlalchemy import SQLAlchemy
from flask import current_app, g
from sqlalchemy import MetaData
from plaintextpass.models import WebAuthnUserAccount, Password

from plaintextpass.models import db as _db

import secrets

def generate_password_id(n):
    generated_password_id = secrets.randbelow(max(n, secrets.DEFAULT_ENTROPY))
    while Password.query.filter(Password.password_id == generated_password_id).count() > 0:
        generated_password_id = secrets.randbelow(max(n, secrets.DEFAULT_ENTROPY))

    return generated_password_id

def get_db():
    try:
        if 'db' not in g:
            g.db = _db
    except RuntimeError:
        return _db
    return g.db

def close_db(e = None):
    db = g.pop('db', None)
    if db is not None:
        db.close_all_sessions()
        db.engine.dispose()

def create_user(user_id, email, username, display_name, password, icon_url, webauthn_credential):
    if type(webauthn_credential.credential_id) == bytes:
        webauthn_credential.credential_id = str(
            webauthn_credential.credential_id, 'utf-8')
    if type(webauthn_credential.public_key) == bytes:
        webauthn_credential.public_key = str(
            webauthn_credential.public_key, 'utf-8')

    db = get_db()
    new_user = WebAuthnUserAccount(
        user_id = user_id,
        email = email,
        username = username,
        display_name = display_name,
        icon_url = icon_url,
        password = password,
        pub_key = webauthn_credential.public_key,
        credential_id = webauthn_credential.credential_id,
        sign_count = webauthn_credential.sign_count,
        rp_id = current_app.config['RP_ID']
    )
    db.session.add(new_user)
    db.session.commit()
    return True

def username_password_matches(username, password):
    return (WebAuthnUserAccount.query
        .filter(WebAuthnUserAccount.username == username)\
        .filter(WebAuthnUserAccount.password == password).count()) > 0

def get_user_by_name(username):
    return WebAuthnUserAccount.query.filter(WebAuthnUserAccount.username == username).first()

def username_exists(username):
    return (WebAuthnUserAccount.query.filter(WebAuthnUserAccount.username == username).count() > 0)

def credential_exists(credential):
    if type(credential) == bytes:
        credential = credential.decode('utf8')
    return (WebAuthnUserAccount.query.filter(WebAuthnUserAccount.credential_id == credential).count() > 0)

def delete_user(user_id):
    pass

def add_password(user_id, domain, account_username, account_password):
    db = get_db()
    created_password = Password(
        user_id = user_id,
        password_id = generate_password_id(current_app.config['PASSWORD_ID_MAX']),
        domain = domain,
        username = account_username,
        password = account_password
        )
    db.session.add(created_password)
    db.session.commit()

def get_password(user_id, password_id):
    try:
        return Password.query\
            .filter(Password.user_id == user_id)\
            .filter(Password.password_id == password_id).first()
    except Exception as e:
        return None

def modify_password(user_id, password_id, domain, account_username, account_password):
    db = get_db()
    updated_password = get_password(user_id, password_id)
    updated_password.user_id = user_id
    updated_password.password_id = password_id
    updated_password.domain = domain
    updated_password.username = account_username
    updated_password.password = account_password
    db.session.add(updated_password)
    db.session.commit()

def count_passwords_for_user(user_id):
    return Password.query\
        .filter(Password.user_id == user_id)\
        .count()

def get_all_passwords_for_user(user_id):
    return Password.query\
        .filter(Password.user_id == user_id)\
        .order_by(Password.domain)\
        .all()

def delete_password_db(user_id, password_id):
    db = get_db()
    remove_password = get_password(user_id, password_id)
    db.session.delete(remove_password)
    db.session.commit()

def init_db(app):
    with app.app_context():
        _db.init_app(app)
        _db.metadata.create_all(_db.engine)

def init_app(app):
    app.teardown_appcontext(close_db)
