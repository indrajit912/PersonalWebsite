# Teaching Blueprint

from flask import Blueprint

teaching_bp = Blueprint(
    'teaching', 
    __name__,
    template_folder="templates", 
    static_folder="static",
    url_prefix='/teaching'
)

from app.teaching import routes