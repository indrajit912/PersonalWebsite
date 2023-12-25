# errors/__init__.py
from flask import Blueprint

errors_bp = Blueprint(
    'errors', 
    __name__, 
    url_prefix='/errors', 
    template_folder="templates", 
    static_folder="static",
    static_url_path="/errors/static"
)

from app.errors import handlers