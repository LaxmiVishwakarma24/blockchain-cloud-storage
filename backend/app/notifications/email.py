from flask import current_app


def send_password_reset(user, reset_url):
    """Placeholder until real email delivery is built.

    DEV ONLY: in debug mode the link is printed to the terminal (not to the log).
    """
    if current_app.debug:
        print(f"[DEV ONLY] Password reset link for {user.email}: {reset_url}")