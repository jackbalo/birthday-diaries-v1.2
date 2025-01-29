import pyotp
from datetime import datetime
from flask import redirect, render_template, url_for, flash
from flask_login import current_user
from flask_mail import Message
from functools import wraps
from app.models import AuditLogs, db, Users

from twilio.rest import Client
from email.mime.text import MIMEText
import smtplib



# Temporary OTP storage (use Redis or DB in production)
otps = {}

def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def password_set(f):
    """
    Decorate routes to require login.
    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("main.login"))
    
        if not current_user.password_set:
            flash("Please set a Password to continue")
            return redirect(url_for("main.add_password"))
        
        return f(*args, **kwargs)

    return decorated_function

def email_confirmed(f):
    """
    Decorate routes to require verification.
    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("main.login"))
    
        if not current_user.confirmed:
            flash("Account not verified!!")
            return redirect(url_for("main.otp_verification"))
        
        return f(*args, **kwargs)

    return decorated_function


# calculate the age of a friend
def calculate_age(birthdate) ->int: #Take an input birthdate and then output(->) an integer

    #check to see if date format is a date or datetime and if not formats in year-month-day
    if isinstance(birthdate, str): #
        birthdate = datetime.strptime(birthdate, "%Y-%m-%d")
    
    today = datetime.today()
    age = today.year - birthdate.year

    # check if the friend has already celebrated his birthday for the year
    if (today.month, today.day) < (birthdate.month, birthdate.day):
        age -= 1

    return age
#log users action
def log(action):
    user_log = AuditLogs(user_id=current_user.id, action=action, timestamp=datetime.now())
    db.session.add(user_log)
    db.session.commit


#convert to python date.
def date_convert(date):
    return datetime.strptime(date, '%Y-%m-%d').date()


"""OTP and SMS Verification
def generate_otp(user_id):
    '''Generate a random 6-digit OTP'''
    otp = random.randint(100000, 999999)
    otps[user_id] = {"otp": otp, "expires_at": datetime.now() + timedelta(minutes=5)}
    return otp

def verify_otp(user_id, entered_otp):
    '''Verify OTP'''
    if user_id in otps:
        otp_data = otps[user_id]
        if otp_data["otp"] == int(entered_otp) and otp_data["expires_at"] > datetime.now():
            del otps[user_id]  # Remove OTP after verification
            return True
    return False

def send_sms(phone_number, otp):
    '''Send OTP via SMS'''
    account_sid = "your_twilio_account_sid"
    auth_token = "your_twilio_auth_token"
    client = Client(account_sid, auth_token)

    message = client.messages.create(
        body=f"Your verification code is: {otp}",
        from_="+1234567890",  # Your Twilio number
        to=phone_number
    )
    return message.sid

def send_email(recipient_email, otp):
    '''Send OTP via Email'''
    sender_email = "your_email@example.com"
    sender_password = "your_email_password"

    subject = "Verification Code"
    body = f"Your OTP code is: {otp}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
"""
def generate_potp_secret_key():
    return pyotp.random_base32()


def generate_otp_code(potp_secret_key):
    totp = pyotp.TOTP(potp_secret_key, interval=600)
    return totp.now()


def verify_otp_code(potp_secret_key, otp_code):
    totp = pyotp.TOTP(potp_secret_key, interval=600)
    return totp.verify(otp_code)


def send_otp_email(receipient_email, otp_code):
    from app import mail
    msg = Message(
        subject="Your One-Time Password (OTP). ",
        recipients=[receipient_email],
        body=f"Your OTP is: {otp_code}\nThis code is valid for 60 seconds."
    )
    mail.send(msg)
    

def verification_email(user):
    if not user.totp_secret:
        user.totp_secret = generate_potp_secret_key()

    user.last_otp_sent = datetime.now()
    db.session.commit()
    
    otp = generate_otp_code(user.totp_secret)

    try:
        send_otp_email(user.email, otp)
        flash(f"Verification code sent to your email {user.email}. ")
        log(f"otp_email_{(user.email)}")
    except Exception as e:
        flash(f"Failed to send OTP: {str(e)}!")
        log("otp_email_failure")