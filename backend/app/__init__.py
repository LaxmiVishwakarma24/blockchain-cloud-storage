import os
import uuid

from flask import Flask, g, jsonify, redirect, render_template, request, url_for

from .config import APP_NAME, APP_VERSION, Config
from .errors import register_error_handlers
from .extensions import csrf, db, login_manager, migrate
from .logging_config import setup_logging
from .security.headers import register_security_headers

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def create_app(config_class=Config):
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "frontend", "templates"),
        static_folder=os.path.join(BASE_DIR, "frontend", "static"),
    )
    app.config.from_object(config_class)

    setup_logging(app)
    db.init_app(app)
    from .models import User

    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        user = db.session.get(User, int(user_id))
        # A deactivated account loses its session immediately.
        return user if user is not None and user.is_active else None

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify(error="Unauthorized", message="Login required."), 401
        return redirect(url_for("auth.login", next=request.path))

    from .auth import auth_bp
    from .files import files_bp
    from .health import health_bp
    from .users import users_bp

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(files_bp)

    register_error_handlers(app)
    register_security_headers(app)

    from .cli import register_cli

    register_cli(app)

    @app.before_request
    def assign_request_id():
        g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

    @app.after_request
    def log_and_tag(resp):
        resp.headers["X-Request-ID"] = g.get("request_id", "-")
        app.logger.info(
            f"{request.method} {request.path}",
            extra={
                "action": "http_request",
                "status": resp.status_code,
                "request_id": g.get("request_id"),
            },
        )
        return resp

    @app.get("/")
    def index():
        return render_template("index.html", app_name=APP_NAME, version=APP_VERSION)

    return app