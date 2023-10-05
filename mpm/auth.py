import functools
import logging

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from mpm.db import get_db
from mpm.core.security import Security
from mpm_config import LOGGER

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if g.user is not None:
        return redirect(url_for("pm.index"))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username and error is None:
            error = 'Username is required.'
        elif not password and error is None:
            error = 'Password is required.'

        password_check = Security.password_security_check(password)
        if not password_check['password_ok'] and error is None:
            if password_check['length_error'] and error is None:
                error = "Password must be at least 8 characters"
            if password_check['digit_error'] and error is None:
                error = "Password must have at least one digit"
            if password_check['uppercase_error'] and error is None:
                error = "Password must have at least one uppercase character"
            if password_check['lowercase_error'] and error is None:
                error = "Password must have at least one lowercase character"
            if password_check['symbol_error'] and error is None:
                error = "Password must have at least one special character between the following: !#$%&'()*+,-./[\]^_`{|}~"

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                LOGGER.info(f"New user created -> {username}")
            except db.IntegrityError:
                error = f"User {username} is already registered."
                LOGGER.warn(f"User {username} failed to create because it already exists")
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    print(LOGGER.name, " - ", LOGGER.handlers, " - ",LOGGER.parent, " - ",LOGGER.level)
    if g.user is not None:
            return redirect(url_for("pm.index"))
            
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            LOGGER.info(f"User {username} (ID {user['id']}) successfully logged in ")
            return redirect(url_for('index'))
        LOGGER.warn(f"User {username} failed to login with error: {error}")
        flash(error)
    return render_template('auth/login.html')

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@bp.before_app_request
def load_logged_in_user():
    """Load user information if user is logged in at each request.
    """
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


def login_required(view):
    """Decorator for checking on a view whether the user is logged in.
    In case the user is not logged in, it is redirected to the login page
    """
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view