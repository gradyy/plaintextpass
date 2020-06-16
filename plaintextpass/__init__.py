import os

from flask import Flask
from flask import render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from plaintextpass.plaintext_passwords import index

def create_app(test_config = None):
    app = Flask(__name__, instance_relative_config = True)
    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile(os.path.join(app.instance_path, 'config.py'), silent = False)

    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # a simple page that says hello

    from plaintextpass import db
    db.init_app(app)
    db.init_db(app)

    from plaintextpass import auth
    app.register_blueprint(auth.bp)
    auth.init_app(app)

    from plaintextpass import plaintext_passwords
    app.register_blueprint(plaintext_passwords.bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    limiter = Limiter(
        app,
        key_func = get_remote_address,
        default_limits = ["10 per minute", "60 per hour", "240 per day"]
    )

    limiter.exempt(index)

    return app

if __name__ == '__main__':
    FLASK_HOST = 'localhost'
    FLASK_PORT = 4999
    app = create_app()
    app.run(host = FLASK_HOST, port = FLASK_PORT, ssl_context = 'adhoc', debug = True)
