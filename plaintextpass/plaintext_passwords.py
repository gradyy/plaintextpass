
from flask import (
    Blueprint, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for
)

from flask_login import login_required, current_user

from plaintextpass.db import add_password, count_passwords_for_user, delete_password_db, get_password, get_all_passwords_for_user, modify_password
from plaintextpass.models import Password, WebAuthnUserAccount

bp = Blueprint('plaintext_passwords', __name__, url_prefix = '/passwords')

def invalid_field(pw):
    return (not pw) or (len(pw) > current_app.config['MAX_FIELD_LEN'])

@bp.route('/')
@login_required
def index():
    #flash('index page for password manager')
    return render_template('password_manager/index.html',
                           username = current_user.username,
                           user_passwords = get_all_passwords_for_user(
                               current_user.user_id)
                           )

@bp.route('/create', methods = ('GET', 'POST'))
@login_required
def create_password():
    if request.method == 'POST':
        domain = request.form.get('domain')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm')
        if invalid_field(domain):
            flash('invalid domain cannot be saved in plaintextpass', 'Error')
            return render_template('password_manager/create.html')
        if invalid_field(username):
            flash('invalid username cannot be saved in plaintextpass', 'Error')
            return render_template('password_manager/create.html')
        if invalid_field(password):
            flash('invalid password cannot be saved in plaintextpass', 'Error')
            return render_template('password_manager/create.html')
        if password != confirm_password:
            flash('passwords do not match', 'Error')
            return render_template('password_manager/create.html')
        try:
            add_password(current_user.user_id, domain, username, password)
        except Exception as e:
            flash('invalid password cannot be saved in plaintextpass', 'Error')
            return render_template('password_manager/create.html')
        return redirect(url_for('plaintext_passwords.index'))
    if count_passwords_for_user(current_user.user_id) >= current_app.config['USER_PASSWORDS_LIMIT']:
        flash('Cannot create new password: limit of {} passwords per account'.format(current_app.config['USER_PASSWORDS_LIMIT']), 'Error')
        return redirect(url_for('plaintext_passwords.index'), 500)
    return render_template('password_manager/create.html')

@bp.route('/edit/<int:password_id>', methods = ('GET', 'POST'))
@login_required
def update_password(password_id):
    saved_password = get_password(current_user.user_id, password_id)
    if not saved_password:
        flash('invalid password selected', 'Error')
        return redirect(url_for('plaintext_passwords.index'))

    if request.method == 'POST':
        domain = request.form.get('domain')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm')
        if password != confirm_password:
            flash('passwords do not match or password invalid', 'Error')
            return render_template('password_manager/update.html',
                                   password_id = saved_password.password_id,
                                   old_domain = saved_password.domain,
                                   old_username = saved_password.username
                                   )
        if invalid_field(domain):
            flash('invalid domain cannot be saved in plaintextpass', 'Error')
            return render_template('password_manager/create.html')
        if invalid_field(username):
            flash('invalid username cannot be saved in plaintextpass', 'Error')
            return render_template('password_manager/create.html')
        if invalid_field(password):
            flash('invalid password cannot be saved in plaintextpass', 'Error')
            return render_template('password_manager/create.html')
        modify_password(current_user.user_id, saved_password.password_id, domain, username, password)
        flash('Password updated for {}@{}'.format(username, domain), 'Info')
        return redirect(url_for('plaintext_passwords.index'))

    return render_template('password_manager/update.html',
                           password_id = saved_password.password_id,
                           old_domain = saved_password.domain,
                           old_username = saved_password.username
                           )

@bp.route('/view/<int:password_id>', methods = ('GET', 'POST'))
@login_required
def read_password(password_id):
    saved_password = get_password(current_user.user_id, password_id)
    if not saved_password:
        flash('invalid password selected', 'Error')
        return redirect(url_for('plaintext_passwords.index'))

    return render_template('password_manager/read.html',
                           password_id = password_id,
                           domain = saved_password.domain,
                           username = saved_password.username,
                           password = saved_password.password
                           )

@bp.route('/delete/<int:password_id>', methods = ('GET', 'POST'))
@login_required
def delete_password(password_id):
    # TODO: CSRF protection
    if request.method == 'POST':
        delete_password_db(current_user.user_id, password_id)
        flash('Password deleted', 'Info')
        return redirect(url_for('plaintext_passwords.index'))

    saved_password = get_password(current_user.user_id, password_id)
    if not saved_password:
        flash('invalid password selected', 'Error')
        return redirect(url_for('plaintext_passwords.index'))
    return render_template('password_manager/delete.html',
                           password_id = password_id,
                           domain = saved_password.domain,
                           username = saved_password.username,
                           password = saved_password.password
                           )
