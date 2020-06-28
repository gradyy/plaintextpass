import functools
import webauthn
import secrets

from flask import (
    Blueprint, current_app, escape, flash, jsonify, redirect, render_template, request, session, url_for
)
from flask_login import (
    LoginManager, login_required, login_user, logout_user
)

from plaintextpass.db import *

bp = Blueprint('auth', __name__, url_prefix = '/auth')
login_manager = LoginManager()

def generate_challenge(challenge_len):
    return secrets.token_urlsafe(max(challenge_len, secrets.DEFAULT_ENTROPY))

def invalid_username(username):
    return (not username) or len(username) < current_app.config['MIN_USERNAME_LEN'] or len(username) > current_app.config['MAX_FIELD_LEN']

def invalid_email(email):
    #TODO
    #additional email validation
    return (not email)

@bp.route('/create-webauthn-credential', methods = ('POST',))
def start_webauthn_registration():

    #username and challenges saved in session
    #needed for server-side validation of webauthn response

    if invalid_username(request.form.get('username', '')):
        flash('invalid username. Username must be between {} and {} characters'.format(
            current_app.config['MIN_USERNAME_LEN'],
            current_app.config['MAX_FIELD_LEN']
            ), 'error')
        return jsonify({'fail': 'Registration failed'})

    if invalid_username(request.form.get('displayName', '')):
        flash('invalid display name. Display name must be between 4 and 50 characters', 'error')
        return jsonify({'fail': 'Registration failed'})

    if invalid_email(request.form.get('email', '')):
        flash('invalid email. please provide a valid email', 'error')
        return jsonify({'fail': 'Registration failed'})

    session['register_username'] = request.form.get('username', '')
    session['register_password'] = request.form.get('password', '')
    session['register_display_name'] = request.form.get('displayName', '')
    session['register_email'] = request.form.get('email', '')

    session['register_challenge'] = generate_challenge(current_app.config['CHALLENGE_LEN'])
    session['register_user_id'] = generate_challenge(current_app.config['CHALLENGE_LEN'])

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge = session['register_challenge'],
        rp_name = current_app.config['RP_NAME'],
        rp_id = current_app.config['RP_ID'],
        user_id = session['register_user_id'],
        username = session['register_username'],
        display_name = session['register_display_name'],
        icon_url = '',
        attestation = 'indirect')
    return jsonify(make_credential_options.registration_dict)

@bp.route('/register-webauthn-credential', methods = ('POST',))
def register_webauthn_user():

    #debug variables
    #request_id = request.form['id']
    #request_rawid = request.form['rawId']
    #request_type = request.form['type']
    #request_attObj = request.form['attObj']
    #request_clientData = request.form['clientData']
    #request_registrationClientExtensions = request.form['registrationClientExtensions']

    #username = session['register_username']
    #password = session['register_password']
    #challenge = session['register_challenge']

    if not session.get('register_user_id', '') \
            or not session.get('register_username', '') \
            or not session.get('register_challenge', ''):
        #passwords are optional, don't check for one here
        flash('WebAuthn registration failed', 'Error')
        return jsonify({'fail': 'Registration failed'})

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        rp_id = current_app.config['RP_ID'],
        origin = current_app.config['RP_ORIGIN'],
        registration_response = request.form,
        challenge = session['register_challenge'],
        #trust_anchor_dir,
        trusted_attestation_cert_required = False, #not required for plaintextpass
        self_attestation_permitted = True,
        none_attestation_permitted = True,
        uv_required = False # User Verification
    )
    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        flash('WebAuthn registration failed', 'Error')
        return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})

    # Step 17.
    #
    # Check that the credentialId is not yet registered to any other user.
    # If registration is requested for a credential that is already registered
    # to a different user, the Relying Party SHOULD fail this registration
    # ceremony, or it MAY decide to accept the registration, e.g. while deleting
    # the older registration.
    try:
        if credential_exists(webauthn_credential.credential_id):
            flash('WebAuthn registration failed', 'Error')
            return jsonify({'fail': 'Credential cannot be registered to this user'})
        if username_exists(session['register_username']):
            flash('WebAuthn registration failed', 'Error')
            return jsonify({'fail': 'WebAuthn registration failed'})
        #add the user to the db
        if create_user(
            user_id = session['register_user_id'],
            email = session['register_email'],
            username = session['register_username'],
            display_name = session['register_display_name'],
            password = session['register_password'],
            icon_url = '',
            webauthn_credential = webauthn_credential):
            return jsonify({'success': 'user registered', 'redirect': url_for('auth.register_success', username = session['register_username'])})
        else:
            flash('WebAuthn registration failed', 'Error')
            return jsonify({'fail': 'WebAuthn registration failed'})
    except Exception as e:
        db = get_db()
        db.session.rollback()
        flash('WebAuthn registration failed', 'Error')
        return jsonify({'error': 'WebAuthn registration failed'})
    finally:
        session.pop('register_user_id', None)
        session['register_completion_username'] = session.pop('register_username', '')
        session.pop('register_display_name', None)
        session.pop('register_email', None)
        session.pop('register_password', None)
        session.pop('register_challenge', None)

@bp.route('/create-webauthn-authentication-request', methods = ('POST',))
def start_webauthn_authenticate():
    username = session['login_username']
    user = get_user_by_name(username)
    #Error handling
    if not user:
        flash('failed to login', 'Error')
        return jsonify({'fail': 'Login failed'})
    if not user.credential_id:
        flash('failed to login', 'Error')
        return jsonify({'fail': 'Login failed'})

    session.pop('challenge', None)
    challenge = generate_challenge(current_app.config['CHALLENGE_LEN'])

    # We strip the padding from the challenge stored in the session
    # for the reasons outlined in the comment in webauthn_begin_activate.
    session['challenge'] = challenge.rstrip('=')

    webauthn_user = webauthn.WebAuthnUser(
        user.user_id,
        user.username,
        user.display_name,
        user.icon_url,
        user.credential_id,
        user.pub_key,
        user.sign_count,
        user.rp_id
    )

    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
        webauthn_user, challenge)

    return jsonify(webauthn_assertion_options.assertion_dict)

@bp.route('/verify-webauthn-authentication-request', methods = ('POST',))
def authenticate_webauthn_user():
    username = session['login_username']
    challenge = session.get('challenge')
    assertion_response = request.form

    user = get_user_by_name(username)

    webauthn_user = webauthn.WebAuthnUser(
        user.user_id,
        user.username,
        user.display_name,
        user.icon_url,
        user.credential_id,
        user.pub_key,
        user.sign_count,
        user.rp_id
    )

    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user,
        assertion_response,
        challenge,
        current_app.config['RP_ORIGIN'],
        uv_required = False  # User Verification
    )

    try:
        sign_count = webauthn_assertion_response.verify()
    except Exception as e:
        flash('WebAuthn assertion failed', 'Error')
        return jsonify({'fail': 'WebAuthn assertion failed'})

    user.sign_count = sign_count
    db = get_db()
    db.session.add(user)
    db.session.commit()

    login_user(user)
    return jsonify({'success': 'logged in as {}'.format(username),
                    'redirect': url_for('plaintext_passwords.index')})

@bp.route('/register', methods = ('GET', 'POST'))
def register():
    return render_template('auth/register.html')

@bp.route('/registrationComplete/<string:username>', methods = ('GET',))
def register_success(username):
    return render_template('auth/register_success.html',
        username = escape(username))

@bp.route('/login', methods = ('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        session['login_username'] = username
        #note: insecure password checking

        if (username == '') or not username_password_matches(username, password):
            flash('Username or password incorrect', 'Error')
            return render_template('auth/login.html')
        #redirect to next handler
        return render_template('auth/login_webauthn.html',
                               username = username
                               )
    return render_template('auth/login.html')

@bp.route('/aboutPasswords', methods = ('GET',))
def about_passwords():
    return render_template('auth/about_passwords.html')

def init_app(app):
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = 'strong'

@login_manager.user_loader
def load_user(user_id):
    return WebAuthnUserAccount.query.filter(WebAuthnUserAccount.user_id == user_id).first()

@login_manager.unauthorized_handler
def unauthorized():
    flash(login_manager.login_message, login_manager.login_message_category)
    return redirect(url_for('auth.login'), 401)

@bp.route('/acct')
@login_required
def acct():
    flash('it works')
    return render_template('auth/register.html')

@bp.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('You are now logged out', 'Info')
    return redirect(url_for('auth.login'))
