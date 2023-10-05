import datetime
import time
from pytz import timezone

from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash

from mpm.auth import login_required
from mpm.db import get_db
from mpm.forms.password_manager_forms import UpdatePasswordForm, UpdateObject, ViewPasswordForm
from mpm.core.security import Security

bp = Blueprint('pm', __name__)

STANDARD_TIMEZONE = "Europe/Rome"

def get_standard_timestamp():
    now_time = datetime.datetime.now(timezone(STANDARD_TIMEZONE))
    timestamp = now_time.strftime('%Y-%m-%d %H:%M:%S')
    return timestamp


@bp.route('/')
@login_required
def index():
    db = get_db()
    passwords = db.execute(
        'SELECT p.id, p.service, p.username, p.password, p.created, p.author_id, p.lastupdated, u.username as user'
        ' FROM passwords p JOIN user u on p.author_id = u.id where p.author_id = ?'
        ' ORDER BY service ASC',
        (  g.user['id'], )
    ).fetchall()
    print(f"==> Fetched passwords for user = {passwords}")
    return render_template('pm/index.html', passwords=passwords)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        password = request.form['password']
        error = None

        if not service:
            error = 'Service is required.'
        
        if not username and error is None:
            error = 'Username is required.'
        
        if not password and error is None:
            error = 'Password is required.'
        

        if error is not None:
            flash(error)
        else:
            hashed = Security.encrypt(password)
            db = get_db()
            db.execute(
                'INSERT INTO passwords (author_id, service, username, password, created)'
                ' VALUES (?, ?, ?, ?, ?)',
                (g.user['id'], service, username, hashed, get_standard_timestamp())
            )
            db.commit()
            return redirect(url_for('pm.index'))

    return render_template('pm/create.html')


def get_password(id, check_author=True):
    password = get_db().execute(
        'SELECT p.id, p.service, p.username, p.password, p.author_id, u.username as user'
        ' FROM passwords p JOIN user u ON p.author_id = u.id'
        ' WHERE p.id = ?',
        (id,)
    ).fetchone()

    print(f"==> Get password res: {password}")

    if password is None:
        abort(404, f"Password id {id} doesn't exist.")

    if check_author and password['author_id'] != g.user['id']:
        abort(403)

    return password


@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    password = get_password(id)
    old_password_decrypted = Security.decrypt(password['password'])
    updateform = UpdatePasswordForm(obj=UpdateObject(password['service'], password['username'], old_password_decrypted))
    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        newpassword = request.form['password']
        error = None

        if newpassword == old_password_decrypted:
            error = "Inserted password is the same. Either change your password or cancel the operation."
        newhash = Security.encrypt(newpassword)
        

        if not service and error is None:
            error = 'Service is required.'
        
        if not username and error is None:
            error = 'Username is required.'
        
        if not newpassword and error is None:
            error = 'Password is required.'

        if error is not None:
            flash(error)
        else:
            
            db = get_db()
            db.execute(
                'UPDATE passwords SET service = ?, username = ?, password = ?, lastupdated = ?'
                ' WHERE id = ?',
                (service, username, newhash, get_standard_timestamp(), id)
            )
            db.commit()
            return redirect(url_for('pm.index'))

    return render_template('pm/update.html', password=password, decrypted_password=old_password_decrypted, form=updateform)

@bp.route('/<int:id>/view', methods=('GET',))
@login_required
def view(id):
    password = get_password(id)
    old_password_decrypted = Security.decrypt(password['password'])
    updateform = ViewPasswordForm(obj=UpdateObject(password['service'], password['username'], old_password_decrypted))
    if request.method == 'POST':
        service = request.form['service']
        username = request.form['username']
        newpassword = request.form['password']
        error = None

        if newpassword == old_password_decrypted:
            error = "Inserted password is the same. Either change your password or cancel the operation."
        newhash = Security.encrypt(newpassword)
        

        if not service and error is None:
            error = 'Service is required.'
        
        if not username and error is None:
            error = 'Username is required.'
        
        if not newpassword and error is None:
            error = 'Password is required.'

        if error is not None:
            flash(error)
        else:
            
            db = get_db()
            db.execute(
                'UPDATE passwords SET service = ?, username = ?, password = ?, lastupdated = ?'
                ' WHERE id = ?',
                (service, username, newhash, get_standard_timestamp(), id)
            )
            db.commit()
            return redirect(url_for('pm.index'))

    return render_template('pm/view.html', password=password, decrypted_password=old_password_decrypted, form=updateform)

@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    get_password(id)
    db = get_db()
    db.execute('DELETE FROM passwords WHERE id = ?', (id,))
    db.commit()
    return redirect(url_for('pm.index'))