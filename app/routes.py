from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from app import db
from app.models import User, Question, QuizResult, RiskBehavior, PhishingReport
import random
import csv
from flask import Response
from datetime import datetime
import os

main = Blueprint('main', __name__)

@main.route('/recreate_db')
def recreate_db():
    """Emergency route to recreate database - remove in production"""
    try:
        # Import all models to ensure they're registered
        from app.models import User, Question, QuizResult, QuizAnswer, RiskBehavior, PhishingReport, AuditLog, EmployeeBehaviorReport

        db.drop_all()
        db.create_all()

        flash("Database recreated successfully with all tables!", "success")
        return "Database recreated successfully! All tables including EmployeeBehaviorReport have been created. You can now register/login again."
    except Exception as e:
        return f"Error recreating database: {e}", 500

@main.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        print(f"Error rendering homepage: {e}")
        return f"Error: {e}", 500

@main.route('/about')
def about():
    return render_template('about.html')

@main.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        organization = request.form.get('organization', '')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # Here you would typically send an email or save to database
        # For now, we'll just flash a success message
        flash(f'Thank you for your message, {name}! We will get back to you within 24 hours.', 'success')
        return redirect(url_for('main.contact'))

    return render_template('contact.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password)

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return redirect(url_for('main.login'))

        # Check if this is the first user
        is_first_user = User.query.count() == 0

        user = User(username=username, email=email, password=hashed_pw, is_admin=is_first_user, is_super_admin=is_first_user)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully!', 'success')

        if is_first_user:
            flash('You have been assigned admin privileges.', 'success')

        return redirect(url_for('main.login'))

    return redirect(url_for('main.login'))


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            user.last_login = datetime.utcnow()
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Login failed. Check credentials.', 'error')

    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/dashboard')
@login_required
def dashboard():
    # Get quiz results for the current user (oldest first)
    results = QuizResult.query.filter_by(user_id=current_user.id).order_by(QuizResult.date_taken.asc()).all()

    dates = []
    scores = []
    risk_data = []

    for result in results:
        # Ensure date_taken exists and format it
        date_str = result.date_taken.strftime('%Y-%m-%d') if result.date_taken else "Unknown"
        score = round(result.score, 2)

        # Risk calculation
        if score >= 80:
            risk = "Low"
        elif score >= 50:
            risk = "Medium"
        else:
            risk = "High"

        # Prepare data for template
        dates.append(date_str)
        scores.append(score)
        risk_data.append({
            'date': date_str,
            'score': score,
            'risk': risk
        })

    return render_template(
        "dashboard.html",
        risk_data=risk_data,
        dates=dates,
        scores=scores
    )




@main.route('/quiz', methods=['GET', 'POST'])
@login_required
def quiz():
    if request.method == 'POST':
        score = 0
        answers = request.form
        quiz_answers = []

        # Create quiz result first
        result = QuizResult(user_id=current_user.id, score=0)  # Will update score later
        db.session.add(result)
        db.session.flush()  # Get the ID

        for q_id, user_ans in answers.items():
            if q_id == 'csrf_token':
                continue  # ✅ Skip CSRF token

            question = Question.query.get(int(q_id))
            if question:
                is_correct = user_ans == question.correct_option
                if is_correct:
                    score += 1

                # Store individual answer
                from app.models import QuizAnswer
                quiz_answer = QuizAnswer(
                    quiz_result_id=result.id,
                    question_id=question.id,
                    user_answer=user_ans,
                    is_correct=is_correct
                )
                db.session.add(quiz_answer)

        total_questions = len(answers) - 1  # exclude csrf_token
        if total_questions > 0:
            final_score = (score / total_questions) * 100
        else:
            final_score = 0

        # Update the result with final score
        result.score = final_score

        # Generate employee behavior report based on quiz performance
        behavior_report = generate_employee_behavior_report(current_user, result, quiz_answers)

        # Store the behavior report
        from app.models import EmployeeBehaviorReport
        report = EmployeeBehaviorReport(
            user_id=current_user.id,
            quiz_result_id=result.id,
            behavior_assessment=behavior_report['assessment'],
            risk_indicators=behavior_report['risk_indicators'],
            recommendations=behavior_report['recommendations'],
            overall_rating=behavior_report['overall_rating']
        )
        db.session.add(report)
        db.session.commit()

        flash(f'Quiz submitted! Your score: {final_score:.2f}%', 'success')
        flash('Employee behavior report generated successfully!', 'info')
        return redirect(url_for('main.view_behavior_report', report_id=report.id))

    all_questions = Question.query.all()
    selected = random.sample(all_questions, min(len(all_questions), 15))
    return render_template('quiz.html', questions=selected)


@main.route('/admin/questions')
@login_required
def manage_questions():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = 20

    questions = Question.query.paginate(
        page=page, 
        per_page=per_page, 
        error_out=False
    )

    return render_template('admin_questions.html', questions=questions)

@main.route('/admin/questions/add', methods=['GET', 'POST'])
@login_required
def add_question():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        q = Question(
            text=request.form['text'],
            option_a=request.form['option_a'],
            option_b=request.form['option_b'],
            option_c=request.form['option_c'],
            option_d=request.form['option_d'],
            correct_option=request.form['correct_option']
        )
        db.session.add(q)
        db.session.commit()
        flash('Question added', 'success')
        return redirect(url_for('main.manage_questions'))

    return render_template('admin_add_question.html')

@main.route('/admin/questions/delete/<int:id>')
@login_required
def delete_question(id):
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    q = Question.query.get_or_404(id)
    db.session.delete(q)
    db.session.commit()
    flash("Question deleted", "success")
    return redirect(url_for('main.manage_questions'))


@main.route('/export/scores')
@login_required
def export_scores():
    try:
        import csv
        import io

        # Get quiz results with proper eager loading
        results = db.session.query(QuizResult).options(
            db.joinedload(QuizResult.answers).joinedload(QuizAnswer.question)
        ).filter_by(user_id=current_user.id).order_by(QuizResult.date_taken.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'Quiz Date', 'Overall Score (%)', 'Risk Level', 'Question #', 'Question Text', 
            'Option A', 'Option B', 'Option C', 'Option D', 
            'Correct Answer', 'Your Answer', 'Result'
        ])

        # Write data
        for result in results:
            quiz_date = result.date_taken.strftime('%Y-%m-%d %H:%M:%S')
            overall_score = f"{result.score:.2f}"

            # Determine risk level
            if result.score >= 80:
                risk_level = "Low Risk"
            elif result.score >= 50:
                risk_level = "Medium Risk"
            else:
                risk_level = "High Risk"

            if result.answers:  # Detailed answers available
                for i, answer in enumerate(result.answers, 1):
                    question = answer.question
                    result_text = "CORRECT" if answer.is_correct else "INCORRECT"

                    writer.writerow([
                        quiz_date, overall_score, risk_level, i, question.text,
                        question.option_a, question.option_b, 
                        question.option_c, question.option_d,
                        question.correct_option, answer.user_answer, 
                        result_text
                    ])
            else:
                # Fallback for old results
                writer.writerow([
                    quiz_date, overall_score, risk_level, 'N/A', 'Detailed data not available',
                    '', '', '', '', '', '', ''
                ])

        output.seek(0)
        response = Response(output.getvalue(), mimetype='text/csv',
                          headers={"Content-Disposition": f"attachment; filename=quiz_results_{current_user.username}.csv"})
        return response

    except Exception as e:
        flash(f"Export failed: {str(e)}", "error")
        return redirect(url_for('main.dashboard'))

@main.route('/admin/questions/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_question(id):
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    question = Question.query.get_or_404(id)

    if request.method == 'POST':
        question.text = request.form['text']
        question.option_a = request.form['option_a']
        question.option_b = request.form['option_b']
        question.option_c = request.form['option_c']
        question.option_d = request.form['option_d']
        question.correct_option = request.form['correct_option']
        db.session.commit()
        flash("Question updated successfully", "success")
        return redirect(url_for('main.manage_questions'))

    return render_template('admin_edit_question.html', question=question)

@main.route('/admin/questions/import-csv', methods=['POST'])
@login_required
def import_csv():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.manage_questions'))

    if 'csv_file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('main.manage_questions'))

    file = request.files['csv_file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('main.manage_questions'))

    if not file.filename.lower().endswith('.csv'):
        flash('Please upload a CSV file', 'error')
        return redirect(url_for('main.manage_questions'))

    try:
        import io
        import csv as csv_module

        # Read the file content
        content = file.stream.read()
        
        # Try different encodings
        for encoding in ['utf-8', 'utf-8-sig', 'iso-8859-1', 'cp1252']:
            try:
                decoded_content = content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            flash('Unable to decode file. Please ensure it\'s a valid CSV file.', 'error')
            return redirect(url_for('main.manage_questions'))

        # Create StringIO object
        stream = io.StringIO(decoded_content)
        
        # Try different delimiters
        for delimiter in [',', '\t', ';']:
            stream.seek(0)
            sample = stream.read(1024)
            stream.seek(0)
            
            # Count columns with this delimiter
            sample_lines = sample.split('\n')[:3]  # Check first 3 lines
            avg_columns = 0
            for line in sample_lines:
                if line.strip():
                    avg_columns += len(line.split(delimiter))
            
            if avg_columns > 0:
                avg_columns = avg_columns / len([l for l in sample_lines if l.strip()])
                if avg_columns >= 6:  # We need at least 6 columns
                    break
        else:
            delimiter = ','  # Default fallback

        # Reset stream and create CSV reader
        stream.seek(0)
        csv_reader = csv_module.reader(stream, delimiter=delimiter)

        added_count = 0
        skipped_count = 0
        errors = []
        processed_rows = 0
        header_row = None

        # Get existing questions to avoid duplicates
        existing_questions = {q.text.strip().lower() for q in Question.query.all()}
        
        for row_num, row in enumerate(csv_reader, 1):
            try:
                processed_rows += 1
                
                # Skip empty rows
                if not row or not any(cell.strip() for cell in row):
                    continue

                # Clean the row
                row = [cell.strip() for cell in row]

                # Check if this is a header row
                if row_num == 1 and any(header in row[0].lower() for header in ['question', 'text']):
                    header_row = [col.lower().strip() for col in row]
                    continue

                # Handle different CSV formats
                if header_row:
                    # Use header-based mapping
                    if len(row) != len(header_row):
                        errors.append(f"Row {row_num}: Column count mismatch with header")
                        continue
                    
                    # Create a mapping from header to data
                    data_map = dict(zip(header_row, row))
                    
                    # Extract question text (try different possible column names)
                    question_text = None
                    for key in ['question', 'text', 'question_text']:
                        if key in data_map:
                            question_text = data_map[key].strip()
                            break
                    
                    # Extract options (try different possible column names)
                    option_a = data_map.get('option_a', data_map.get('a', '')).strip()
                    option_b = data_map.get('option_b', data_map.get('b', '')).strip()
                    option_c = data_map.get('option_c', data_map.get('c', '')).strip()
                    option_d = data_map.get('option_d', data_map.get('d', '')).strip()
                    
                    # Extract correct answer (try different possible column names)
                    correct_option = None
                    for key in ['correct_answer', 'answer', 'correct_option', 'correct']:
                        if key in data_map:
                            correct_option = data_map[key].strip().upper()
                            break
                else:
                    # Use positional mapping (legacy format)
                    # Determine if first column is an ID (numeric)
                    start_index = 0
                    if len(row) > 0 and row[0].isdigit():
                        start_index = 1

                    # Check if we have enough columns
                    if len(row) < start_index + 6:
                        errors.append(f"Row {row_num}: Need at least 6 columns")
                        continue

                    # Extract data positionally
                    question_text = row[start_index].strip()
                    option_a = row[start_index + 1].strip()
                    option_b = row[start_index + 2].strip()
                    option_c = row[start_index + 3].strip()
                    option_d = row[start_index + 4].strip()
                    correct_option = row[start_index + 5].strip().upper()

                # Validate required fields
                if not all([question_text, option_a, option_b, option_c, option_d, correct_option]):
                    errors.append(f"Row {row_num}: All fields are required")
                    continue

                # Validate correct option
                if correct_option not in ['A', 'B', 'C', 'D']:
                    errors.append(f"Row {row_num}: Correct answer must be A, B, C, or D (got: {correct_option})")
                    continue

                # Check for duplicates
                if question_text.lower() in existing_questions:
                    skipped_count += 1
                    continue

                # Create new question
                new_question = Question(
                    text=question_text,
                    option_a=option_a,
                    option_b=option_b,
                    option_c=option_c,
                    option_d=option_d,
                    correct_option=correct_option
                )

                db.session.add(new_question)
                existing_questions.add(question_text.lower())  # Track for this session
                added_count += 1

            except Exception as e:
                errors.append(f"Row {row_num}: {str(e)}")
                continue

        # Commit to database
        try:
            if added_count > 0:
                db.session.commit()
                flash(f'Successfully imported {added_count} questions!', 'success')
            else:
                flash('No new questions were imported', 'warning')

            if skipped_count > 0:
                flash(f'Skipped {skipped_count} duplicate questions', 'info')

            if errors:
                flash(f'{len(errors)} errors encountered during import', 'warning')
                # Show first few errors
                for error in errors[:5]:
                    flash(f"• {error}", 'warning')
                if len(errors) > 5:
                    flash(f"• ... and {len(errors) - 5} more errors", 'warning')

        except Exception as e:
            db.session.rollback()
            flash(f'Database error: {str(e)}', 'error')

    except Exception as e:
        flash(f'Error processing CSV file: {str(e)}', 'error')

    return redirect(url_for('main.manage_questions'))


@main.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    search_query = request.args.get('q', '')
    if search_query:
        users = User.query.filter(
            (User.username.ilike(f'%{search_query}%')) |
            (User.email.ilike(f'%{search_query}%'))
        ).all()
    else:
        users = User.query.all()

    return render_template("admin_users.html", users=users, search_query=search_query)

@main.route('/admin/users/promote/<int:user_id>')
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f"{user.username} promoted to admin", "success")
    return redirect(url_for('main.manage_users'))

@main.route('/admin/users/demote/<int:user_id>')
@login_required
def demote_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)
    if user.is_super_admin:
        flash("Cannot demote the super admin.", "error")
        return redirect(url_for('main.manage_users'))

    user.is_admin = False
    db.session.commit()
    flash(f"{user.username} demoted from admin", "success")
    return redirect(url_for('main.manage_users'))

@main.route('/admin/users/toggle/<int:user_id>')
@login_required
def toggle_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)
    if user.is_super_admin:
        flash("Cannot deactivate the super admin.", "error")
        return redirect(url_for('main.manage_users'))

    user.is_active = not user.is_active
    db.session.commit()
    status = "activated" if user.is_active else "deactivated"
    flash(f"{user.username} {status}", "success")
    return redirect(url_for('main.manage_users'))

@main.route('/admin/users/reset-password/<int:user_id>', methods=['GET', 'POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        if new_password:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash(f"Password reset successfully for {user.username}", "success")
            return redirect(url_for('main.manage_users'))
        else:
            flash("Password cannot be empty", "error")

    return render_template('admin_reset_password.html', user=user)

@main.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    total_users = User.query.count()
    total_quizzes = QuizResult.query.count()
    avg_score = db.session.query(db.func.avg(QuizResult.score)).scalar() or 0

    # 🆕 Add quiz data for chart and table
    quiz_data = db.session.query(User.username, QuizResult.score, QuizResult.date_taken).join(User).order_by(QuizResult.date_taken.desc()).all()

    # Chart data
    labels = [q.username for q in quiz_data]
    scores = [round(q.score, 2) for q in quiz_data]
    
    # Get phishing report statistics
    phishing_total = PhishingReport.query.count()
    phishing_pending = PhishingReport.query.filter_by(status='pending').count()
    phishing_verified = PhishingReport.query.filter_by(status='verified').count()
    phishing_false = PhishingReport.query.filter_by(status='false_positive').count()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_quizzes=total_quizzes,
        avg_score=round(avg_score, 2),
        quiz_data=quiz_data,
        labels=labels,
        scores=scores,
        phishing_total=phishing_total,
        phishing_pending=phishing_pending,
        phishing_verified=phishing_verified,
        phishing_false=phishing_false
    )

@main.route('/admin/audit')
@login_required
def audit_logs():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin_audit.html', logs=logs)

@main.route('/export_results')
@login_required
def export_results():
    try:
        import csv
        import io
        from flask import make_response

        # Get user's quiz results with proper eager loading to avoid session issues
        results = db.session.query(QuizResult).options(
            db.joinedload(QuizResult.answers).joinedload(QuizAnswer.question)
        ).filter_by(user_id=current_user.id).order_by(QuizResult.date_taken.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            'Quiz Date', 'Overall Score (%)', 'Risk Level', 'Question #', 'Question Text', 
            'Option A', 'Option B', 'Option C', 'Option D', 
            'Correct Answer', 'Your Answer', 'Result'
        ])

        # Write data
        for result in results:
            quiz_date = result.date_taken.strftime('%Y-%m-%d %H:%M:%S')
            overall_score = f"{result.score:.2f}"

            # Determine risk level
            if result.score >= 80:
                risk_level = "Low Risk"
            elif result.score >= 50:
                risk_level = "Medium Risk"
            else:
                risk_level = "High Risk"

            if result.answers:  # Detailed answers available
                for i, answer in enumerate(result.answers, 1):
                    question = answer.question
                    result_text = "CORRECT" if answer.is_correct else "INCORRECT"

                    writer.writerow([
                        quiz_date, overall_score, risk_level, i, question.text,
                        question.option_a, question.option_b, 
                        question.option_c, question.option_d,
                        question.correct_option, answer.user_answer, 
                        result_text
                    ])
            else:
                # Fallback for old results
                writer.writerow([
                    quiz_date, overall_score, risk_level, 'N/A', 'Detailed data not available',
                    '', '', '', '', '', '', ''
                ])

        output.seek(0)

        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=detailed_quiz_results_{current_user.username}.csv'

        return response

    except Exception as e:
        flash(f"Export failed: {str(e)}", "error")
        return redirect(url_for('main.dashboard'))

# API Endpoints for Chrome Extension

@main.route('/api/report-phishing', methods=['POST'])
def report_phishing():
    try:
        data = request.get_json()

        # Create phishing report
        report = PhishingReport(
            url=data.get('url'),
            domain=data.get('domain'),
            title=data.get('title'),
            user_id=current_user.id if current_user.is_authenticated else None,
            details=str(data.get('branding', {}))
        )

        db.session.add(report)
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Report received'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@main.route('/api/log-behavior', methods=['POST'])
def log_behavior():
    try:
        data = request.get_json()

        # Create risk behavior log
        behavior = RiskBehavior(
            user_id=current_user.id if current_user.is_authenticated else None,
            behavior_type=data.get('type'),
            domain=data.get('domain'),
            details=str(data),
            risk_score=calculate_behavior_risk_score(data.get('type'))
        )

        db.session.add(behavior)
        db.session.commit()

        # Update user's overall risk score
        if current_user.is_authenticated:
            update_user_risk_score(current_user.id)

        return jsonify({'status': 'success'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

def calculate_behavior_risk_score(behavior_type):
    """Calculate risk score based on behavior type"""
    risk_scores = {
        'suspicious_login_page': 25,
        'attempted_login_on_suspicious_site': 50,
        'clicked_suspicious_link': 30,
        'downloaded_suspicious_file': 40,
        'entered_credentials_on_http': 35
    }
    return risk_scores.get(behavior_type, 10)

def generate_employee_behavior_report(user, quiz_result, quiz_answers):
    """Generate comprehensive employee behavior report based on quiz performance"""
    score = quiz_result.score

    # Analyze answer patterns
    incorrect_answers = [qa for qa in quiz_answers if not qa['is_correct']]
    total_questions = len(quiz_answers)

    # Behavior assessment based on score ranges
    if score >= 85:
        assessment = "Excellent cybersecurity awareness. Employee demonstrates strong understanding of security protocols."
        overall_rating = "Excellent"
        risk_indicators = ["Low risk profile", "Strong security mindset", "Follows best practices"]
    elif score >= 70:
        assessment = "Good cybersecurity awareness with room for improvement in specific areas."
        overall_rating = "Good"
        risk_indicators = ["Moderate risk profile", "Generally security-conscious", "Some knowledge gaps identified"]
    elif score >= 50:
        assessment = "Fair cybersecurity awareness. Requires additional training and monitoring."
        overall_rating = "Fair"
        risk_indicators = ["Elevated risk profile", "Basic security understanding", "Multiple knowledge gaps"]
    else:
        assessment = "Poor cybersecurity awareness. Immediate training intervention required."
        overall_rating = "Poor"
        risk_indicators = ["High risk profile", "Limited security understanding", "Significant training needs"]

    # Generate specific recommendations
    recommendations = []
    if score < 85:
        recommendations.append("Enroll in advanced phishing awareness training")
    if score < 70:
        recommendations.append("Regular security briefings and updates")
        recommendations.append("Implement additional email security measures")
    if score < 50:
        recommendations.append("Mandatory cybersecurity certification required")
        recommendations.append("Enhanced monitoring of digital activities")
        recommendations.append("One-on-one security coaching sessions")

    # Add behavioral insights based on incorrect answers
    if len(incorrect_answers) > total_questions * 0.3:
        recommendations.append("Focus on practical security scenarios training")

    return {
        'assessment': assessment,
        'risk_indicators': '; '.join(risk_indicators),
        'recommendations': '; '.join(recommendations) if recommendations else "Continue current security practices",
        'overall_rating': overall_rating
    }

def update_user_risk_score(user_id):
    """Update user's overall risk score based on recent behaviors"""
    from datetime import datetime, timedelta

    # Get behaviors from last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_behaviors = RiskBehavior.query.filter(
        RiskBehavior.user_id == user_id,
        RiskBehavior.timestamp >= thirty_days_ago
    ).all()

    # Calculate weighted risk score
    total_risk = sum(behavior.risk_score for behavior in recent_behaviors)
    behavior_count = len(recent_behaviors)

    # Get quiz performance
    recent_quiz = QuizResult.query.filter_by(user_id=user_id).order_by(QuizResult.date_taken.desc()).first()
    quiz_risk = 0
    if recent_quiz:
        if recent_quiz.risk_level == 'High':
            quiz_risk = 40
        elif recent_quiz.risk_level == 'Medium':
            quiz_risk = 20
        else:
            quiz_risk = 5

    # Combined risk score (behavior 60%, quiz 40%)
    if behavior_count > 0:
        combined_risk = (total_risk * 0.6) + (quiz_risk * 0.4)
    else:
        combined_risk = quiz_risk

    # Update user record
    user = User.query.get(user_id)
    if user:
        user.risk_score = min(100, combined_risk)
        db.session.commit()

@main.route('/admin/phishing-reports')
@login_required
def phishing_reports():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    page = request.args.get('page', 1, type=int)
    reports = PhishingReport.query.order_by(PhishingReport.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('admin_phishing_reports.html', reports=reports)

@main.route('/admin/report-status/<int:id>/<status>')
@login_required
def update_report_status(id, status):
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    report = PhishingReport.query.get_or_404(id)
    if status in ['pending', 'verified', 'false_positive']:
        report.status = status
        db.session.commit()
        flash(f"Report status updated to {status}", "success")
    else:
        flash("Invalid status", "error")

    return redirect(url_for('main.phishing_reports'))

@main.route('/api/report-details/<int:id>')
@login_required
def get_report_details(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    report = PhishingReport.query.get_or_404(id)
    return jsonify({
        'id': report.id,
        'url': report.url,
        'domain': report.domain,
        'title': report.title,
        'details': report.details,
        'status': report.status,
        'timestamp': report.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    })

@main.route('/admin/risk-behaviors')
@login_required
def risk_behaviors():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    page = request.args.get('page', 1, type=int)
    user_filter = request.args.get('user', 'all')
    
    # Base query
    query = RiskBehavior.query
    
    # Apply user filter if specified
    if user_filter != 'all' and user_filter.isdigit():
        query = query.filter(RiskBehavior.user_id == int(user_filter))
    
    # Get all users for the filter dropdown
    users = User.query.all()
    
    # Get users with risk behaviors
    users_with_behaviors = db.session.query(User).join(RiskBehavior).distinct().all()
    
    # Paginate the results
    behaviors = query.order_by(RiskBehavior.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False
    )

    return render_template('admin_risk_behaviors.html', behaviors=behaviors, users=users, 
                           users_with_behaviors=users_with_behaviors, current_filter=user_filter)

@main.route('/admin/add-sample-risk-behaviors')
@login_required
def add_sample_risk_behaviors():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))
    
    # Get all users
    users = User.query.all()
    
    if not users:
        flash("No users found. Please create some users first.", "error")
        return redirect(url_for('main.risk_behaviors'))
    
    # Sample behavior types
    behavior_types = [
        "clicked_suspicious_link",
        "downloaded_suspicious_file",
        "shared_credentials",
        "visited_phishing_site",
        "opened_suspicious_email"
    ]
    
    # Sample domains
    domains = [
        "suspicious-site.com",
        "fake-bank.com",
        "malware-download.net",
        "phishing-attempt.org",
        "free-prize-winner.com"
    ]
    
    # Add 3 risk behaviors for each user
    for user in users:
        for i in range(3):
            behavior_type = random.choice(behavior_types)
            domain = random.choice(domains)
            risk_score = random.randint(10, 50)  # Random score between 10 and 50
            
            # Create risk behavior
            risk_behavior = RiskBehavior(
                user_id=user.id,
                behavior_type=behavior_type,
                domain=domain,
                details=f"Sample risk behavior for testing purposes - {behavior_type} on {domain}",
                risk_score=risk_score
            )
            
            db.session.add(risk_behavior)
    
    db.session.commit()
    flash("Sample risk behaviors added successfully!", "success")
    return redirect(url_for('main.risk_behaviors'))

@main.route('/admin/risk-behavior/<int:behavior_id>')
@login_required
def view_risk_behavior(behavior_id):
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))
    
    # Get the risk behavior
    behavior = RiskBehavior.query.get_or_404(behavior_id)
    
    return render_template('admin_risk_behavior_detail.html', behavior=behavior)

@main.route('/extension')
def extension_guide():
    return render_template('extension_guide.html')

@main.route('/download-extension')
def download_extension():
    try:
        import zipfile
        import os
        from flask import send_file
        import tempfile

        # Create temporary zip file
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')

        with zipfile.ZipFile(temp_zip.name, 'w') as zipf:
            # Add extension files (these would be the actual files from chrome_extension folder)
            extension_files = [
                ('manifest.json', '''
{
  "manifest_version": 3,
  "name": "Phishing Awareness - Fake Login Detector",
  "version": "1.0.0",
  "description": "Detects fake login pages and prevents phishing attacks",
  "permissions": ["activeTab", "storage", "scripting"],
  "host_permissions": ["<all_urls>"],
  "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"], "run_at": "document_end"}],
  "background": {"service_worker": "background.js"},
  "action": {"default_popup": "popup.html", "default_title": "Phishing Detector"}
}'''),
                ('content.js', open('chrome_extension/content.js', 'r').read() if os.path.exists('chrome_extension/content.js') else '// Content script placeholder'),
                ('popup.html', open('chrome_extension/popup.html', 'r').read() if os.path.exists('chrome_extension/popup.html') else '<!-- Popup HTML placeholder -->'),
                ('popup.js', open('chrome_extension/popup.js', 'r').read() if os.path.exists('chrome_extension/popup.js') else '// Popup script placeholder'),
                ('background.js', open('chrome_extension/background.js', 'r').read() if os.path.exists('chrome_extension/background.js') else '// Background script placeholder')
            ]

            for filename, content in extension_files:
                zipf.writestr(filename, content)

        temp_zip.close()

        return send_file(temp_zip.name, as_attachment=True, download_name='phishing_detector_extension.zip', mimetype='application/zip')

    except Exception as e:
        flash(f"Download failed: {str(e)}", "error")
        return redirect(url_for('main.extension_guide'))
# app/routes.py

@main.route('/api/check-auth', methods=['GET'])
def check_auth():
    if current_user.is_authenticated:
        return jsonify({"is_authenticated": True}), 200
    return jsonify({"is_authenticated": False}), 401

@main.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            # In a real app, you'd send an email with a reset token
            # For now, we'll just set a temporary password
            temp_password = f"temp_{user.id}_{datetime.utcnow().strftime('%Y%m%d')}"
            user.password = generate_password_hash(temp_password)
            db.session.commit()

            flash(f'Password reset! Your temporary password is: {temp_password}', 'success')
            flash('Please login and change your password immediately.', 'info')
            return redirect(url_for('main.login'))
        else:
            flash('Email not found in our system.', 'error')

    return render_template('forgot_password.html')

@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        elif len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
        else:
            current_user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('main.dashboard'))

    return render_template('change_password.html')

@main.route('/behavior-report/<int:report_id>')
@login_required
def view_behavior_report(report_id):
    from app.models import EmployeeBehaviorReport
    try:
        report = EmployeeBehaviorReport.query.get_or_404(report_id)

        # Ensure user can only view their own reports (unless admin)
        if not current_user.is_admin and report.user_id != current_user.id:
            flash("Access denied", "error")
            return redirect(url_for('main.dashboard'))

        return render_template('behavior_report.html', report=report)
    except Exception as e:
        if "no such table" in str(e):
            flash("Database needs to be updated. Please recreate the database.", "warning")
        else:
            flash(f"Error loading report: {str(e)}", "error")
        return redirect(url_for('main.dashboard'))

@main.route('/behavior-report/<int:report_id>/pdf')
@login_required
def download_report_pdf(report_id):
    from app.models import EmployeeBehaviorReport
    from flask import make_response
    import os
    import tempfile
    from io import BytesIO
    import logging
    
    try:
        report = EmployeeBehaviorReport.query.get_or_404(report_id)
        
        # Ensure user can only download their own reports (unless admin)
        if not current_user.is_admin and report.user_id != current_user.id:
            flash("Access denied", "error")
            return redirect(url_for('main.dashboard'))
        
        # Generate HTML content for the PDF
        html = render_template('behavior_report_pdf.html', report=report)
        
        # Create HTML response as fallback
        html_response = make_response(html)
        html_response.headers['Content-Type'] = 'text/html'
        html_response.headers['Content-Disposition'] = f'inline; filename=behavior_report_{report_id}.html'
        
        # Try different PDF generation methods
        pdf_generated = False
        
        # Try using pdfkit if available
        if not pdf_generated:
            try:
                import pdfkit
                try:
                    # Check if wkhtmltopdf is installed
                    config = pdfkit.configuration()
                    # Try using pdfkit directly
                    pdf_content = pdfkit.from_string(html, False, configuration=config)
                    
                    # Create response with PDF
                    response = make_response(pdf_content)
                    response.headers['Content-Type'] = 'application/pdf'
                    response.headers['Content-Disposition'] = f'attachment; filename=behavior_report_{report_id}.pdf'
                    
                    pdf_generated = True
                    return response
                except Exception as pdf_error:
                    # Log the error
                    logging.error(f"PDF generation error with pdfkit: {str(pdf_error)}")
                    print(f"PDF generation error with pdfkit: {str(pdf_error)}")
            except ImportError as ie:
                logging.error(f"pdfkit import error: {str(ie)}")
                print(f"pdfkit import error: {str(ie)}")
        
        # If pdfkit failed, try WeasyPrint
        if not pdf_generated:
            try:
                import weasyprint
                try:
                    pdf_file = BytesIO()
                    weasyprint.HTML(string=html).write_pdf(pdf_file)
                    pdf_file.seek(0)
                    
                    # Create response with PDF
                    response = make_response(pdf_file.getvalue())
                    response.headers['Content-Type'] = 'application/pdf'
                    response.headers['Content-Disposition'] = f'attachment; filename=behavior_report_{report_id}.pdf'
                    
                    pdf_generated = True
                    return response
                except Exception as weasy_error:
                    # Log the error
                    logging.error(f"PDF generation error with WeasyPrint: {str(weasy_error)}")
                    print(f"PDF generation error with WeasyPrint: {str(weasy_error)}")
            except ImportError as ie:
                logging.error(f"WeasyPrint import error: {str(ie)}")
                print(f"WeasyPrint import error: {str(ie)}")
        
        # If all PDF methods failed, return HTML as fallback
        if not pdf_generated:
            flash("PDF generation failed. Displaying HTML version instead.", "warning")
            return html_response
            
    except Exception as e:
        logging.error(f"Error generating PDF: {str(e)}")
        flash(f"Error generating PDF: {str(e)}", "error")
        return redirect(url_for('main.view_behavior_report', report_id=report_id))

@main.route('/my-behavior-reports')
@login_required
def my_behavior_reports():
    from app.models import EmployeeBehaviorReport
    try:
        reports = EmployeeBehaviorReport.query.filter_by(user_id=current_user.id).order_by(EmployeeBehaviorReport.created_at.desc()).all()
    except Exception as e:
        # If table doesn't exist, return empty list and recreate database
        if "no such table" in str(e):
            flash("Database needs to be updated. Please recreate the database.", "warning")
            reports = []
        else:
            flash(f"Error loading reports: {str(e)}", "error")
            reports = []
    return render_template('my_behavior_reports.html', reports=reports)

@main.route('/admin/behavior-reports')
@login_required
def admin_behavior_reports():
    if not current_user.is_admin:
        flash("Access denied", "error")
        return redirect(url_for('main.dashboard'))

    from app.models import EmployeeBehaviorReport
    try:
        page = request.args.get('page', 1, type=int)
        reports = EmployeeBehaviorReport.query.order_by(EmployeeBehaviorReport.created_at.desc()).paginate(
            page=page, per_page=20, error_out=False
        )
    except Exception as e:
        if "no such table" in str(e):
            flash("Database needs to be updated. Please recreate the database.", "warning")
            # Create empty pagination object
            from flask_sqlalchemy import Pagination
            reports = Pagination(None, 1, 20, 0, [])
        else:
            flash(f"Error loading reports: {str(e)}", "error")
            from flask_sqlalchemy import Pagination
            reports = Pagination(None, 1, 20, 0, [])

    return render_template('admin_employee_reports.html', reports=reports)