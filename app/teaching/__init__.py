# Teaching Blueprint

from flask import Blueprint

teaching_bp = Blueprint(
    'teaching', 
    __name__,
    template_folder="templates", 
    static_folder="static",
    static_url_path="/teaching/static",
    url_prefix='/teaching'
)

from app.teaching import routes