from flask import Flask


def create_app(test_config=None):
    app = Flask(__name__)
    # app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    app.config.from_mapping(
        # a default secret that should be overridden by instance config
        SECRET_KEY="thisisasecretkey",
        RECAPTCHA_PUBLIC_KEY='6LdMHXAiAAAAACouP_eGKx_x6KYgrAwnPIQUIpNe',
        RECAPTCHA_PRIVATE_KEY='6LdMHXAiAAAAAP3uAfsgPERmaMdA9ITnVIK1vn9W',
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.update(test_config)

    from app.flaskapp.main import login_manager
    login_manager.init_app(app)

    # against attacks such as Cross site request forgery (CSRF)
    from app.flaskapp.main import bcrypt
    bcrypt.init_app(app)

    from app.flaskapp.main import csrf
    csrf.init_app(app)  # globally enable csrf protection within the application

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.update(test_config)

    from app.flaskapp import main
    app.register_blueprint(main.mainapp)

    return app
