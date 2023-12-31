import os
import datetime
import pytz
import subprocess

from pprint import pprint
from flask import Flask
from flask import (g, redirect)
from flask import render_template, send_from_directory

from mpm_config import LOGGER, BASE_PATH


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'mpm.sqlite'),
    )
    
    x = subprocess.run(["pip","list"], capture_output=True, universal_newlines=True)
    pprint(f"=====> PIP LIST: {x}")

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    ### Blueprints & DB
    # Initialize database
    from . import db
    #db_exists = os.path.exists(os.path.join(BASE_PATH, "instance"))
    #if not db_exists:
    #    x = subprocess.run(["flask", "--app", "app", "init-db"], capture_output=True,universal_newlines=True)
    #    LOGGER.debug(str(x))
    db.init_app(app)
    LOGGER.debug("Successfully initialised app database")

    # Initialize authentication blueprint
    from . import auth
    app.register_blueprint(auth.bp)
    LOGGER.debug("Successfully registered auth blueprint")

    # Initialize pm blueprint
    from . import pm
    app.register_blueprint(pm.bp)
    app.add_url_rule('/', endpoint='index')
    LOGGER.debug("Successfully registered pm blueprint")

    now = pytz.timezone('Europe/Warsaw').localize(datetime.datetime.now())
    LOGGER.debug(f"My Password Manager application launched! => Europe/Rome date = {now}")


    # a simple page that says hello
    @app.route('/hello')
    def hello():
        return 'Hello, World!'
    
    @app.route('/michi')
    def michi():
        user = g.user
        msg = ""
        if user is not None:
            msg = f"User {user['username']} (ID {user['id']}) visited private Michi page"
        else:
            msg = f"Unlogged user visited private Michi page"
        LOGGER.info(msg)
        return render_template('michi.html')

    # Initialize security encryption key
    from mpm.core.security import Security
    if not Security.key_exists():
        _ = Security.generate_key()

    # Error handlers
    # Error handling functions
    @app.errorhandler(404)
    def page_not_found(error):
        user = g.user
        msg = ""
        if user is not None:
            msg = f"User {user['username']} reached 404 page"
        else:
            msg = f"Unlogged user reached 404 page"
        LOGGER.warn(msg) 
        return render_template("404.html"), 404
    
    @app.errorhandler(500)
    def internal_server_error(error):
        return 'Internal server error', 500
    
    return app