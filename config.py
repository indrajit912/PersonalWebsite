"""
Config file for my website!

Author: Indrajit Ghosh
Created On: Dec 22, 2023
"""

import os
from os.path import join, dirname
from dotenv import load_dotenv
from pathlib import Path
from secrets import token_hex

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)

BASE_DIR = Path(__file__).parent.resolve()
APP_DATA_DIR = Path(__file__).parent / "app_data"


class EmailConfig:
    INDRAJITS_BOT_EMAIL_ID = os.environ.get("INDRAJITS_BOT_EMAIL_ID")
    INDRAJITS_BOT_EMAIL_PASSWD = os.environ.get("INDRAJITS_BOT_APP_PASSWORD")
    INDRAJIT912_GMAIL = os.environ.get("INDRAJIT912_GMAIL")
    GMAIL_SERVER = ['smtp.gmail.com', 587]
    
    HERMES_API_KEY = os.environ.get("HERMES_API_KEY")
    HERMES_EMAILBOT_ID = os.environ.get("HERMES_EMAILBOT_ID")
    HERMES_BASE_URL = "https://hermesbot.pythonanywhere.com"

class DatabaseConfig:
    # Below are the PlanetScale db credentials
    DB_HOST = os.environ.get("DB_HOST")
    DB_USERNAME = os.environ.get("DB_USERNAME")
    DB_PASSWORD = os.environ.get("DB_PASSWORD")
    DB_NAME = os.environ.get("DB_NAME")

    # Database URI
    # Check if any of the required credentials is None
    if None in (DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME):
        pscale_connection_uri = None
    else:
        # Construct the Planet Scale Database URI
        pscale_connection_uri = (
            f"mysql+mysqlconnector://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
            "?ssl_ca=/etc/ssl/cert.pem"
        )

class DevelopmentConfig:
    DEBUG = True
    SECRET_KEY = os.environ.get('SECRET_KEY') or token_hex(16)


class ProductionConfig:
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or token_hex(16)
