import json
import logging
import os
import uuid
from datetime import datetime

from flask import Flask, g, request, has_request_context
from flask_cors import CORS
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = "erp.login"
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        req_id = getattr(g, "request_id", None)
        if req_id:
            payload["request_id"] = req_id
        if has_request_context():
            payload["path"] = request.path
            payload["method"] = request.method
        return json.dumps(payload)


def setup_logging(app: Flask):
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    app.logger.handlers = [handler]
    app.logger.setLevel(level)


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/erpdb"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    cors_origins = os.getenv("CORS_ALLOWED_ORIGINS", "*")
    CORS(app, resources={r"/api/*": {"origins": [x.strip() for x in cors_origins.split(",") if x.strip()]}})

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)
    setup_logging(app)

    @app.before_request
    def attach_request_id():
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

    @app.after_request
    def append_response_headers(response):
        response.headers["X-Request-ID"] = g.request_id
        return response

    from . import routes

    app.register_blueprint(routes.bp)

    return app
