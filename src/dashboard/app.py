import secrets

from flask import Flask

from src.dashboard.routes.auth_routes import auth_bp
from src.dashboard.routes.main_routes import main_bp
from src.dashboard.routes.api_routes  import api_bp


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    return app


def run(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    import os
    from pathlib import Path
    os.chdir(Path(__file__).parent.parent.parent)
    app = create_app()
    app.run(host=host, port=port, debug=debug, use_reloader=False)
