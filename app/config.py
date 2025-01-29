import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Configure session to use filesystem (instead of signed cookies)
    SESSION_PERMANENT = False
    SESSION_TYPE = "filesystem"

    SECRET_KEY = os.getenv("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = "sqlite:///project.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # list of google scopes - https://developers.google.com/identity/protocols/oauth2/scopes

    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
    GOOGLE_SCOPE = os.getenv("GOOGLE_SCOPE")
    GOOGLE_META_URL = os.getenv("GOOGLE_META_URL")



    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_SERVER = os.getenv("MAIL_SERVER")
    MAIL_PORT = 587
    MAIL_USERNAME =  os.getenv("MAIL_USERNAME")
    MAIL_PASSWORD =  os.getenv("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_PASSWORD")
