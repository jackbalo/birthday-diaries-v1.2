import requests
import pyotp

from flask import flash, redirect, render_template, request, session, abort, Blueprint, url_for
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message, Mail
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from app.models import  db, Users, Birthdays, AuditLogs
from app.helpers import apology, log, calculate_age, date_convert, password_set, generate_otp_code, send_otp_email, verify_otp_code, generate_potp_secret_key, email_confirmed, verification_email

from sqlalchemy.sql import func


main_bp = Blueprint('main', __name__)
POTP_SECRET_KEY = pyotp.random_base32()

@main_bp.route("/")
def index():
    """Homepage"""
    # Forget any user_id
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    return render_template("index.html")


@main_bp.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        phone = request.form.get("phone")
        dob = request.form.get("dob")
        name = request.form.get("name")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password, method='pbkdf2:sha256:600000', salt_length=16)
            
        if not username or not password or not email or not phone or not name:
            return apology("All fields are required!! ", 400)
        
        if password != confirmation:
            return apology("Password Mismatch!! ", 400)
        
        try:
            user = Users(name=name, username=username, hash=hash, dob=dob, email=email, phone=phone, password_set=True, totp_secret = generate_potp_secret_key())
            db.session.add(user)
            db.session.commit()

            user = Users.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.hash,password):
                return apology("Invalid Username or Password!! ", 404)

            login_user(user)
            log("register")

        except ValueError:
            return apology("Username already exists!! ", 403)
        
        verification_email(current_user)
        return redirect(url_for("main.otp_verification"))
    
    else:
        return render_template("register.html")
    

@main_bp.route("/otp_verification", methods=["GET", "POST"])
@login_required
@password_set
def otp_verification():
    if request.method == "POST":
        if 'resend_otp' in request.form:
            time_last_otp_sent = None
            if current_user.last_otp_sent: 
                time_last_otp_sent = (datetime.now() - current_user.last_otp_sent).total_seconds()  
                if time_last_otp_sent and time_last_otp_sent < 60:
                    flash(f"Resend otp in {60 - int(time_last_otp_sent)} seconds!! ")
                else:
                    verification_email(current_user)
                return redirect(url_for("main.otp_verification"))
            else:
                verification_email(current_user)
            return redirect(url_for("main.otp_verification"))
        else:
            otp = request.form.get("otp")
            if not otp:
                flash("Please Enter OTP! ")
                return redirect(url_for("main.otp_verification"))
            
            if verify_otp_code(current_user.totp_secret, otp):
                current_user.confirmed = True
                current_user.confirmed_on = datetime.now()
                db.session.commit()
                flash("OTP verification successful! ")
                log("otp_verified")
                return redirect(url_for("main.home"))
            else: 
                flash("Invalid or expired OTP!! ")
                log("OTP_verification_failed!! ")
                return redirect(url_for("main.otp_verification"))
            
    time_last_otp_sent = None
    if current_user.last_otp_sent: 
        time_last_otp_sent = (datetime.now() - current_user.last_otp_sent).total_seconds()
        countdown = max(0, int(60 - time_last_otp_sent)) if time_last_otp_sent else 60

    return render_template("otp_verification.html", user=current_user, countdown=countdown)


@main_bp.route("/add_password", methods=["GET", "POST"])
def add_password():
    """Register user"""
    if current_user.password_set:
        flash("Already added Password")
        return redirect(url_for("main.index"))

    if request.method == "POST":
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        if not password or not confirmation:
            return apology("All fields are required!!", 400)
        
        if password != confirmation:
            return apology("Password Mismatch", 400)
        
        current_user.hash = generate_password_hash(password, method='pbkdf2:sha256:600000', salt_length=16)
        current_user.password_set = True
        db.session.commit()

        log("google_register")

        if not current_user.confirmed:
            verification_email(current_user)
            return redirect(url_for("main.otp_verification"))
    
    return render_template("add_password.html", user=current_user)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return apology("Must provide Username or Password", 403)

        # Query database for username
        user = Users.query.filter_by(username=username).first()

        # Ensure username exists and password is correct
        if not user or not check_password_hash(user.hash, password):
            return apology("invalid username and/or password", 403)

        login_user(user)
        log("log_in")
        return redirect(url_for("main.home"))

    # User reached route via GET (as by clicking a link or via redirect)
    return render_template("login.html")


@main_bp.route("/signin-google")
def googleCallback():
    from app import oauth_client
    # fetch access token and id token using authorization code
    try:
        token = oauth_client.myApp.authorize_access_token()

        personDataUrl = "https://people.googleapis.com/v1/people/me?personFields=genders,birthdays"

        headers = {'Authorization': f'Bearer {token["access_token"]}'}
        response = requests.get(personDataUrl, headers=headers)
        person_info = response.json()

        email = token["userinfo"]["email"]
        name = token["userinfo"]["name"]
        google_id = token["userinfo"]["sub"]
        
        birthday = None
        if "birthdays" in person_info and len(person_info["birthdays"]) > 1:
            date_info = person_info["birthdays"][1].get("date", {})
            day = date_info.get("day")
            month = date_info.get("month")
            year = date_info.get("year")
            birthday = f"{year}-{month:02d}-{day:02d}" if year else f"{month:02d}-{day:02d}"

        user = Users.query.filter_by(email=email).first()
        if not user:
            user = Users(name=name, username=name, dob=birthday, email=email, google_id=google_id, totp_secret=generate_potp_secret_key(), last_otp_sent=datetime.now())
            db.session.add(user)
            db.session.commit()

        login_user(user)

        if not user.password_set:
            return redirect(url_for("main.add_password"))
        
        if not user.confirmed:
            verification_email(current_user)
            return redirect(url_for("main.otp_verification"))
                
        log(f"google_login_{name}")
        return redirect(url_for("main.home"))

    except ValueError:
        return apology("Unauthorized login", 403)

    

@main_bp.route("/google-login")
def googleLogin():
    from app import oauth_client
    if current_user.is_authenticated:
        abort(404)
    return oauth_client.myApp.authorize_redirect(redirect_uri=url_for("main.googleCallback", _external=True))


@main_bp.route("/home")
@login_required
@password_set
@email_confirmed
def home():
    '''Show friends whose birthday is that day'''
    user_id = current_user.id
   
    birthdays = Birthdays.query.filter(func.strftime('%d-%m',Birthdays.birthdates)==func.strftime('%d-%m', func.now()), Birthdays.user_id==user_id).all()

    for friend in birthdays:
        friend.age = calculate_age(friend.birthdates)
    
    return render_template("home.html", birthdays=birthdays)


@main_bp.route("/birthdays")
@login_required
@password_set
@email_confirmed
def birthdays():
    '''list all friends and their birthdays'''
    birthdays = Birthdays.query.filter_by(user_id=current_user.id).all()

    for friend in birthdays:
        friend.age = calculate_age(friend.birthdates)
    
    return render_template("birthdays.html", birthdays=birthdays)


@main_bp.route("/add_birthday", methods=["GET", "POST"])
@login_required
@password_set
@email_confirmed
def add_birthday():
    '''add Friend's birthday'''
    if request.method == "POST":
        email = request.form.get("email")
        phone = request.form.get("phone")
        birthdate = date_convert(request.form.get("birthdate"))
        name = request.form.get("name")
        age = calculate_age(birthdate)

        if not name or not birthdate or not phone or not email:
            flash("All fields are required")
    
        birthday = Birthdays(user_id=current_user.id, name=name, birthdates=birthdate, phone=phone, email=email, age=age)
        db.session.add(birthday)
        db.session.commit()

        log(f"added_{name}")
        flash(f"{name} added successfully")
        return redirect("/birthdays")
    
    return render_template("add.html")


@main_bp.route("/delete_birthday/<int:id>", methods=["GET", "POST"])
@login_required
@password_set
@email_confirmed
def delete_friend(id):
    '''Delete or Change Friend's birthday'''
    friend = Birthdays.query.filter_by(id=id, user_id=current_user.id).first()
    if not friend:
        flash ("Birthday not found!!")
        return redirect(url_for("main.birthdays"))
    name = friend.name
    try:
        db.session.delete(friend)
        db.session.commit()
        log(f"deleted_{name}")
        flash(f"{name} deleted from friends")
    except:
        db.session.rollback()
        flash("An error occurred while deleting birthday")
    
    return redirect(url_for("main.birthdays"))


@main_bp.route("/edit_birthday/<int:id>", methods=["GET", "POST"])
@login_required
@password_set
@email_confirmed
def edit_birthday(id):
    '''Change Friend's birthday'''
    friend= Birthdays.query.filter_by(id=id, user_id = current_user.id).first()

    if not friend:
        flash("not in Friend's list")
        return redirect(url_for("main.birthdays"))
    
    if request.method == "POST":
        friend.email = request.form.get("email") or friend.email
        friend.phone = request.form.get("phone") or friend.phone
        friend.birthdates = date_convert(request.form.get("birthdate")) or friend.birthdates
        friend.name = request.form.get("name") or friend.name

        db.session.commit()

        log(f"edited_{friend.name}")
        flash("Birthday update Successful")
        return redirect(url_for("main.birthdays"))
    
    return render_template("edit.html", friend=friend)


@main_bp.route("/update_profile/<int:id>", methods=["GET", "POST"])
@login_required
@password_set
@email_confirmed
def update_profile(id):
    '''Change Friend's birthday'''
    user = Users.query.get_or_404(id)
    if request.method == "POST":
        current_user.name = request.form.get("name") or current_user.name
        current_user.username = request.form.get("username") or current_user.username
        current_user.email = request.form.get("email") or current_user.email
        current_user.phone = request.form.get("phone") or current_user.phone
        current_user.dob =  request.form.get("dob") or current_user.dob
        password = request.form.get("password")

        if not password or not check_password_hash(current_user.hash, password):
            flash("Enter Valid password")
            return redirect("/update_profile/<int:id>")
        
        db.session.commit()
        log("profile_update")
        flash("Profile updated succefully")
        return redirect("/profile")
    
    
    return render_template("update_profile.html", user=user)
    

@main_bp.route("/logout")
@login_required
def logout():
    """Log user out"""
    #Add to logs
    log("log out")
    logout_user()
    flash("You have successfully logged out of your Diary")
    return redirect(url_for("main.index"))


@main_bp.route("/password_reset", methods=["GET", "POST"])
@login_required
@password_set
@email_confirmed
def password_reset():
    """Change User Password"""
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(new_password, method='pbkdf2:sha256:600000', salt_length=16)
        
        if not old_password:
            flash("Enter Current Password")
            return redirect("/password_reset") 
        
        if not new_password or new_password != confirmation:
            flash("Password Mismatch")
            return redirect("/password_reset")
        
        current_user.hash = hash
        db.session.commit()
        
        log("pword_reset")
        flash("Password Changed Successfully")
        return redirect(url_for("main.profile"))

    return render_template("password_reset.html")


@main_bp.route("/search", methods=["GET", "POST"])
@login_required
@password_set
@email_confirmed
def search():
    """Search for friend"""
    if request.method == "POST":
        name = request.form.get("name")
        if not name:
            flash("Enter valid name")
            return redirect(url_for("main.birthdays"))
        else:
            searched_name = f"%{name}%"
            
            birthdays = Birthdays.query.filter(Birthdays.name.ilike(searched_name)).all()
            if not birthdays:
                flash(f"No friend with name {name}")
                return redirect(url_for("main.birthdays")) 

            for friend in birthdays:
                birthdate = friend.birthdates
                friend.age = calculate_age(birthdate)

        return render_template("birthdays.html", birthdays=birthdays)

    return redirect(url_for("main.home"))
    

@main_bp.route("/profile")
@login_required
@password_set
def profile():
    '''view Your Account'''
    return render_template("profile.html", user=current_user)


@main_bp.route("/delete_account", methods=["GET", "POST"])
@login_required
@password_set
def delete_account():
    '''Delete Your Account'''
    if request.method == "POST":
        password = request.form.get("password")
        
        if not password or not check_password_hash(current_user.hash, password):
            flash("Enter a valid password")
            return redirect("/profile")
        
        friends = Birthdays.query.filter_by(user_id=current_user.id).all()
        
        for friend in friends:
            db.session.delete(friend)
        
        db.session.delete(current_user)
        db.session.commit()
        
        log('account_deleted')
        logout_user()
        flash("Your account has been deactivated")
        
        return redirect(url_for("main.register"))


