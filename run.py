# My Personal Website
#
# Author: Indrajit Ghosh
# Created on: Dec 22, 2023
#

"""
This script starts the Flask development server to run the web application.

Usage:
    python run.py
"""

from app import create_app
from config import DevelopmentConfig

app = create_app(DevelopmentConfig)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    