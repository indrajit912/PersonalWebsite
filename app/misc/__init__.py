# Miscellanous Blueprint

from flask import Blueprint

misc_bp = Blueprint(
    'misc', 
    __name__,
    template_folder="templates", 
    static_folder="static",
    static_url_path="/misc/static",
    url_prefix='/misc'
)

from app.misc import routes