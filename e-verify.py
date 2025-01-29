import flask
from flask_redmail import RedMail

app = flask.Flask(__name__)
email = RedMail(app)

# Configure
app.config["EMAIL_HOST"] = "localhost"
app.config["EMAIL_PORT"] = 0

# Optional
app.config["EMAIL_USERNAME"] = "me@example.com"
app.config["EMAIL_PASSWORD"] = "<PASSWORD>"
app.config["EMAIL_SENDER"] = "no-reply@example.com"



@app.route("/send")
def send_email():
    email.send(
        subject="An example",
        receivers=["you@example.com"],
        html="<h1>An example email.</h1>"
    )




from flask import Flask
from flask_redmail import RedMail
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

email = RedMail()
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    # Configure the sender
    app.config["EMAIL_HOST"] = "localhost"
    app.config["EMAIL_PORT"] = 587
    app.config["EMAIL_USER"] = "me@example.com"
    app.config["EMAIL_PASSWORD"] = "<PASSWORD>"

    # Set some other relevant configurations
    app.config["SECRET_KEY"] = "GUI interface with VBA"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app_data.db"

    email.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

'''
I recently came to the same problem and I decided to solve it by creating a Flask extension to (my) email library. This extension (Flask-Redmail) is pretty similar to Flask-Mail but it is more feature-packed and relies on a well tested and robust library, called Red Mail.

I wrote how I did it here: https://flask-redmail.readthedocs.io/en/latest/cookbook.html#verification-email

In short, what you need to do:

Get the email (and the password) the user specified
Store the user to your user database as an unverified user
Send an email to the user with a unique URL that identifies him/her
Create this URL endpoint and set the user to be verified if visited.
In order to achieve these, I suggest to use:

pyjwt for creating unique tokens
flask-redmail for sending emails
flask-sqlalchemy for database handling
flask-login to create the user and handle login
Next, I'll demonstrate how to do it. Create the file for your application (ie. app.py): '''

from flask import Flask
from flask_redmail import RedMail¨
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

email = RedMail()
db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    
    # Configure the sender
    app.config["EMAIL_HOST"] = "localhost"
    app.config["EMAIL_PORT"] = 587
    app.config["EMAIL_USER"] = "me@example.com"
    app.config["EMAIL_PASSWORD"] = "<PASSWORD>"

    # Set some other relevant configurations
    app.config["SECRET_KEY"] = "GUI interface with VBA"
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app_data.db"

    email.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)

    # Import and set the blueprints/routes
    ...
Create the user class and set login to models.py:

from Trial.app.app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    email = db.Column(db.String, primary_key=True)
    password = db.Column(db.String, nullable=False)
    verified = db.Column(db.Boolean, default=Falsea)


#Then to the route, for example as views.py:

from flask import request, current_app, abort, render_template, BluePrint

# Import your custom instances and models
from Trial.app.app import email, db
from Trial.app.models import User

auth_page = Blueprint('auth', __name__)

@auth_page.route("/create-user", methods=["GET", "POST"])
def create_user():
    if request.method == "GET":
        return render_template("create_user.html")
    elif request.method == "POST":
        # Now we create the user

        # Getting form data (what user inputted)
        data = request.form.to_dict()
        email = data["email"]
        password = data["password"]

        # Verifying the user does not exist
        old_user = User.query.filter_by(id=email).first()
        if old_user:
            abort(403)

        # Encrypt the password here (for example with Bcrypt)
        ...

        # Creating the user
        user = User(
            email=email, 
            password=password,
            verified=False
        )
        db.session.add(user)
        db.session.commit()

        # Create a secure token (string) that identifies the user
        token = jwt.encode({"email": email}, current_app.config["SECRET_KEY"])
        
        # Send verification email
        email.send(
            subject="Verify email",
            receivers=email,
            html_template="email/verify.html",
            body_params={
                "token": token
            }
        )
# Then we create the email body. Flask-Redmail seeks the HTML templates from the application's Jinja environment by default. Do this simply by creating file templates/email/verify.html:


'''<h1>Hi,</h1>
<p>
    in order to use our services, please click the link below:
    <be>
    <a href={{ url_for('verify_email', token=token, _external=True) }}>verify email</a>
</p>
<p>If you did not create an account, you may ignore this message.</p> '''

#Finally, we create a route to handle the verification:

@auth_page.route("/vefify-email/<token>")
def verify_email(token):
    data = jwt.decode(token, current_app.config["SECRET_KEY"])
    email = data["email"]

    user = User.query.filter_by(email=email).first()
    user.verified = True
    db.session.commit()

#Note that you need to templates/create_user.html and models.py where you store your User class.

'''
Some relevant links:

Flask-Redmail's source code
Flask-Redmail's documentation
Flask-Redmail's releases (PyPI)
More about Red Mail:

Red Mail's source code
Red Mail's documentation
Red Mail's releases (PyPI)'''