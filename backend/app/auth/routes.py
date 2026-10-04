from flask import current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import User
from ..notifications.email import send_password_reset
from . import auth_bp, services


def _log(action, status, user_id=None):
    current_app.logger.info(action, extra={"user": user_id, "action": action, "status": status})


def _safe_next(target):
    """Only allow same-site relative paths (blocks open redirects)."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    return target


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = services.validate_registration(email, username, password, confirm)
        if not errors:
            try:
                user = services.register_user(email, username, password)
            except IntegrityError:
                db.session.rollback()
                errors = ["That email or username is already registered."]
            else:
                _log("REGISTER", "SUCCESS", user.id)
                flash("Account created. Please sign in.", "success")
                return redirect(url_for("auth.login"))
        for message in errors:
            flash(message, "danger")
        return render_template("auth/register.html", email=email, username=username), 400
    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))
    next_url = request.values.get("next", "")
    if request.method == "POST":
        user, error = services.authenticate(
            request.form.get("email", ""), request.form.get("password", ""), request.remote_addr
        )
        if error:
            _log("LOGIN", "FAILED")
            flash(error, "danger")
            return render_template("auth/login.html", next_url=next_url), 401
        login_user(user)
        _log("LOGIN", "SUCCESS", user.id)
        return redirect(_safe_next(next_url) or url_for("auth.dashboard"))
    return render_template("auth/login.html", next_url=next_url)


@auth_bp.post("/logout")
@login_required
def logout():
    _log("LOGOUT", "SUCCESS", current_user.id)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.get("/dashboard")
@login_required
def dashboard():
    # Placeholder page. The full dashboard is built in a later phase.
    return render_template("dashboard.html")


@auth_bp.get("/api/auth/me")
@login_required
def me():
    return jsonify(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        role=current_user.role_name,
    )


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        errors = []
        if not current_user.check_password(current):
            errors.append("Current password is incorrect.")
        errors += services.validate_password(new)
        if new != confirm:
            errors.append("New passwords do not match.")
        if not errors and new == current:
            errors.append("New password must differ from the current password.")
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("auth/change_password.html"), 400
        current_user.set_password(new)
        db.session.commit()
        _log("CHANGE_PASSWORD", "SUCCESS", current_user.id)
        flash("Password updated.", "success")
        return redirect(url_for("auth.dashboard"))
    return render_template("auth/change_password.html")


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()
        if user is not None and user.is_active:
            token = services.make_reset_token(user)
            send_password_reset(user, url_for("auth.reset_password", token=token, _external=True))
            _log("FORGOT_PASSWORD", "REQUESTED", user.id)
        # Same message either way, so the form does not reveal which emails exist.
        flash("If that email is registered, a reset link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("auth/forgot_password.html")


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = services.verify_reset_token(token)
    if user is None:
        flash("That reset link is invalid or has expired.", "danger")
        return redirect(url_for("auth.forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        errors = services.validate_password(password)
        if password != confirm:
            errors.append("Passwords do not match.")
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template("auth/reset_password.html"), 400
        user.set_password(password)
        user.failed_login_count = 0
        user.locked_until = None
        db.session.commit()
        _log("RESET_PASSWORD", "SUCCESS", user.id)
        flash("Password reset. Please sign in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html")