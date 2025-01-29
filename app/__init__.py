from flask import Flask
from flask_session import Session
from flask_login import LoginManager
from flask_mail import Mail
from authlib.integrations.flask_client import OAuth
from app.models import db,Users
from app.config import Config
from app.routes import main_bp



oauth_client = OAuth()
mail = Mail()

# Configure application
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config) # load configuration

    Session(app)
    db.init_app(app)
    oauth_client.init_app(app)
    mail.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "main.index"
    
    
    
    @login_manager.user_loader
    def load_user(id):
        return Users.query.get(int(id))

    app.register_blueprint(main_bp)
    
# list of google scopes - https://developers.google.com/identity/protocols/oauth2/scopes
    oauth_client.register(
    name="myApp",
    client_id= app.config["GOOGLE_CLIENT_ID"],
    client_secret= app.config["GOOGLE_CLIENT_SECRET"],
    client_kwargs={
        "scope": "openid profile email https://www.googleapis.com/auth/user.birthday.read https://www.googleapis.com/auth/user.gender.read",
        #'code_challenge_method': 'S256'  # enable PKCE
    },
    server_metadata_url= app.config["GOOGLE_META_URL"]
    )


    @app.after_request
    def after_request(response):
        """Ensure responses aren't cached"""
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response
    

    return app

