from app import db
from flask_login import UserMixin
from app import login_manager
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    is_super_admin = db.Column(db.Boolean, default=False)
    quizzes = db.relationship('QuizResult', backref='user', lazy=True)
    last_login = db.Column(db.DateTime)
    risk_score = db.Column(db.Float, default=0.0)

class Question(db.Model):
    __tablename__ = 'question'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.Text)
    option_b = db.Column(db.Text)
    option_c = db.Column(db.Text)
    option_d = db.Column(db.Text)
    correct_option = db.Column(db.String(1))  # 'A', 'B', 'C', or 'D'

class QuizResult(db.Model):
    __tablename__ = 'quiz_result'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)
    time_taken = db.Column(db.Integer)  # in seconds
    answers = db.relationship('QuizAnswer', backref='quiz_result', lazy=True, cascade='all, delete-orphan')

    @property
    def risk_level(self):
        """Calculate risk level based on score"""
        if self.score >= 80:
            return "Low"
        elif self.score >= 50:
            return "Medium"
        else:
            return "High"

class QuizAnswer(db.Model):
    __tablename__ = 'quiz_answer'
    id = db.Column(db.Integer, primary_key=True)
    quiz_result_id = db.Column(db.Integer, db.ForeignKey('quiz_result.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_answer = db.Column(db.String(1), nullable=False)  # A, B, C, or D
    is_correct = db.Column(db.Boolean, nullable=False)
    question = db.relationship('Question', backref='quiz_answers')

class RiskBehavior(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    behavior_type = db.Column(db.String(100), nullable=False)
    domain = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('risk_behaviors', lazy=True))

class PhishingReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='pending')  # pending, verified, false_positive
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('phishing_reports', lazy=True))


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    admin = db.relationship('User', backref='audit_logs')

class EmployeeBehaviorReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_result_id = db.Column(db.Integer, db.ForeignKey('quiz_result.id'), nullable=False)
    behavior_assessment = db.Column(db.Text, nullable=False)
    risk_indicators = db.Column(db.Text, nullable=False)
    recommendations = db.Column(db.Text, nullable=False)
    overall_rating = db.Column(db.String(50), nullable=False)  # Excellent, Good, Fair, Poor
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('behavior_reports', lazy=True))
    quiz_result = db.relationship('QuizResult', backref=db.backref('behavior_report', uselist=False))