from flask import Blueprint

files_bp = Blueprint("files", __name__)

from . import routes, shares, verification  # noqa: E402,F401