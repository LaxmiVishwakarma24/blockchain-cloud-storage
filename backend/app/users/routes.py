from flask import abort, current_app, jsonify
from flask_login import current_user

from ..extensions import db
from ..models import User
from ..security.decorators import roles_required
from . import users_bp


def _set_active(user_id, active):
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    if user.id == current_user.id and not active:
        return jsonify(error="Bad Request", message="You cannot deactivate your own account."), 400
    user.is_active = active
    db.session.commit()
    action = "ACTIVATE_USER" if active else "DEACTIVATE_USER"
    current_app.logger.info(action, extra={"user": current_user.id, "action": action, "status": "SUCCESS"})
    return jsonify(id=user.id, email=user.email, is_active=user.is_active)


@users_bp.post("/api/users/<int:user_id>/deactivate")
@roles_required("ADMIN")
def deactivate_user(user_id):
    return _set_active(user_id, False)


@users_bp.post("/api/users/<int:user_id>/activate")
@roles_required("ADMIN")
def activate_user(user_id):
    return _set_active(user_id, True)