from app import db
from app.models import AuditLog
from flask_login import current_user

def log_action(action):
    if current_user.is_authenticated and current_user.is_admin:
        entry = AuditLog(admin_id=current_user.id, action=action)
        db.session.add(entry)
        db.session.commit()
