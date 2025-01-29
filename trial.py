@main_bp.route("/otp_verification", methods=["GET", "POST"])
@login_required
@password_set
def otp_verification():
    cooldown_period = 60  # Cooldown period in seconds

    if request.method == "POST":
        otp = request.form.get("otp")
        if not otp:
            flash("Please enter OTP", "danger")
            return redirect(url_for("main.otp_verification"))

        if verify_otp_code(current_user.totp_secret, otp):
            current_user.confirmed = True
            current_user.confirmed_on = datetime.now()
            db.session.commit()
            flash("OTP verification successful", "success")
            log("otp_verified")
            return redirect(url_for("main.home"))
        else:
            flash("Invalid or expired OTP", "danger")
            log("otp_verification_failed")
            return render_template("otp_verification.html", user=current_user)

    # Cooldown check for OTP resend
    if current_user.last_otp_sent:
        time_since_last_otp = (datetime.now() - current_user.last_otp_sent).total_seconds()
        if time_since_last_otp < cooldown_period:
            flash(f"Resend OTP in {int(cooldown_period - time_since_last_otp)} seconds", "warning")
            return render_template("otp_verification.html", user=current_user)

    # Generate and send OTP if cooldown period is over
    current_user.totp_secret = generate_potp_secret_key()
    current_user.last_otp_sent = datetime.now()
    db.session.commit()

    otp = generate_otp_code(current_user.totp_secret)
    try:
        send_otp_email(current_user.email, otp)
        flash(f"Verification code sent to your email {current_user.email}", "success")
        log(f"otp_email_sent to {current_user.email}")
    except Exception as e:
        flash(f"Failed to send OTP: {str(e)}", "danger")
        log("otp_email_failure")

    return render_template("otp_verification.html", user=current_user)
