# Flask Application - Indrajit's Personal Website
#
# Author: Indrajit Ghosh
# Created On: Dec 22, 2023
#

from flask import Flask

from config import ProductionConfig

def create_app(config_class=ProductionConfig):
    """
    Creates an app with specific config class
    """

    # Initialize the webapp
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize the app with db

    # Initialize the app and db with Flask-Migrate

    # Register all blueprints
    from app.main import main_bp
    app.register_blueprint(main_bp)

    from app.teaching import teaching_bp
    app.register_blueprint(teaching_bp)

    from app.errors import errors_bp
    app.register_blueprint(errors_bp)
    

    @app.route('/test/')
    def test_page():
        return '<h1>Testing the Flask Application Factory Pattern</h1>'


    return app

