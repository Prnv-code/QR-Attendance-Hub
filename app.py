from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
import os
import pyotp
from flask import send_file  # Add import at top if not there

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-later'  # A random string for security—change it to something unique
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///attendance.db'  # Our simple database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models (these define our tables: Users, Subjects, Sessions, Attendance)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # We'll hash this later for security
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'teacher' or 'student'

class Subject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.String(10), nullable=False)
    end_time = db.Column(db.String(10), nullable=False)
    qr_code = db.Column(db.String(200))
    is_active = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    secret_key = db.Column(db.String(32), nullable=False, default=lambda: pyotp.random_base32())  # NEW
    subject = db.relationship('Subject', backref='sessions', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.Integer, db.ForeignKey('session.id'), nullable=False)
    scan_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='present')
    session = db.relationship('Session', backref='attendances', lazy=True)
# Create the database tables (runs once)
with app.app_context():
    db.create_all()

# Basic Homepage Route
@app.route('/')
def home():
    return render_template('home.html')  # We'll create this HTML file next

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        role = request.form['role']

        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in instead.', 'error')
            return redirect(url_for('signup'))

        # Create new user
        new_user = User(email=email, name=name, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('home'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Welcome back!', 'success')
            # Redirect based on role
            if user.role == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')

@app.route('/teacher_dashboard')
def teacher_dashboard():
    if 'user_id' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    
    if session['role'] != 'teacher':
        flash('Teachers only.', 'error')
        return redirect(url_for('home'))
    
    check_expired_sessions()  # If you added this earlier
    
    user_id = session['user_id']
    subjects = Subject.query.filter_by(teacher_id=user_id).all()
    sessions = Session.query.filter_by(teacher_id=user_id).all()
    
    # Safe attendee counts (default 0 if query fails)
    total_sessions = len(sessions)
    active_sessions = 0
    total_attendees = 0
    for s in sessions:
        s.attendee_count = Attendance.query.filter_by(session_id=s.id).count() or 0
        if s.is_active:
            active_sessions += 1
        total_attendees += s.attendee_count
    
    return render_template('teacher_dashboard.html', subjects=subjects, sessions=sessions, 
                           total_sessions=total_sessions, active_sessions=active_sessions, total_attendees=total_attendees)


@app.route('/student_dashboard')
def student_dashboard():
    if 'user_id' not in session:
        flash('Please log in.', 'error')
        return redirect(url_for('login'))
    
    if session['role'] != 'student':
        flash('Students only.', 'error')
        return redirect(url_for('home'))
    
    check_expired_sessions()  # If added earlier
    
    user_id = session['user_id']
    attendances = Attendance.query.filter_by(user_id=user_id).join(Session).order_by(Session.date.desc()).all()
    
    # Group for % per subject + missed (per-subject totals)
    subject_stats = {}
    total_present = len(attendances)
    
    for att in attendances:
        subj_id = att.session.subject_id
        subj_name = att.session.subject.name
        if subj_id not in subject_stats:
            total_subj_sessions = Session.query.filter_by(subject_id=subj_id).count()
            present_subj = Attendance.query.filter(Attendance.user_id == user_id, Attendance.session_id == att.session.id).count()
            missed_subj = total_subj_sessions - present_subj
            subject_stats[subj_name] = {
                'present': present_subj, 'total': total_subj_sessions, 
                'percent': round((present_subj / total_subj_sessions * 100) if total_subj_sessions > 0 else 0, 1),
                'missed': missed_subj
            }
    
    # Overall: Sum across subjects (simple global approx)
    overall_total = sum(stats['total'] for stats in subject_stats.values())
    overall_percent = round((total_present / overall_total * 100) if overall_total > 0 else 0, 1)
    
    active_sessions = Session.query.filter_by(is_active=True).all()
    return render_template('student_dashboard.html', attendances=attendances, subject_stats=subject_stats, 
                           total_present=total_present, overall_percent=overall_percent, 
                           active_sessions=active_sessions)

@app.route('/add_subject', methods=['GET', 'POST'])
def add_subject():
    if 'user_id' not in session or session['role'] != 'teacher':
        flash('Access denied. Teachers only.', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        if name:
            new_subject = Subject(name=name, teacher_id=session['user_id'])
            db.session.add(new_subject)
            db.session.commit()
            flash('Subject added!', 'success')
        else:
            flash('Subject name cannot be empty.', 'error')
        return redirect(url_for('teacher_dashboard'))

    return render_template('add_subject.html')

@app.route('/create_session', methods=['GET', 'POST'])
def create_session():
    if 'user_id' not in session or session['role'] != 'teacher':
        flash('Access denied. Teachers only.', 'error')
        return redirect(url_for('home'))

    # Fetch teacher's subjects for dropdown
    subjects = Subject.query.filter_by(teacher_id=session['user_id']).all()

    if request.method == 'POST':
        subject_id = int(request.form['subject_id'])
        date_str = request.form['date']
        start_time = request.form['start_time']
        end_time = request.form['end_time']

        session_date = date.fromisoformat(date_str)
        end_datetime = datetime.combine(session_date, datetime.strptime(end_time, '%H:%M').time())  # Expiry = end_time
        expires_at = end_datetime

        # Check if subject belongs to teacher
        subject = Subject.query.get(subject_id)
        if subject and subject.teacher_id == session['user_id']:
            new_session = Session(
                subject_id=subject_id,
                date=session_date,
                start_time=start_time,
                end_time=end_time,
                expires_at=expires_at,
                teacher_id=session['user_id']
            )
            db.session.add(new_session)
            db.session.commit()
            flash(f'Session for {subject.name} created! QR expires at {end_time}.', 'success')
        else:
            flash('Invalid subject selected.', 'error')

        return redirect(url_for('teacher_dashboard'))

    return render_template('create_session.html', subjects=subjects)

def check_expired_sessions():
    expired_sessions = Session.query.filter(Session.expires_at < datetime.now(), Session.is_active == True).all()
    for ses in expired_sessions:
        ses.is_active = False
    db.session.commit()
    return len(expired_sessions)

@app.route('/generate_qr/<int:session_id>')
def generate_qr(session_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        flash('Access denied. Teachers only.', 'error')
        return redirect(url_for('home'))

    session_obj = Session.query.get_or_404(session_id)
    if session_obj.teacher_id != session['user_id']:
        flash('This is not your session.', 'error')
        return redirect(url_for('teacher_dashboard'))

    # Generate QR code with session ID
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(str(session_id))
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # Save to static/images
    qr_filename = f'qr_{session_id}.png'
    qr_path = os.path.join('static', 'images', qr_filename)
    img.save(qr_path)

    # Update session with QR path
    session_obj.qr_code = f'/static/images/{qr_filename}'
    db.session.commit()

    return render_template('qr_display.html', qr_session=session_obj, timestamp=datetime.now().timestamp())

@app.route('/dynamic_qr/<int:session_id>')
def dynamic_qr(session_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return '', 403
    
    session_obj = Session.query.get_or_404(session_id)
    if session_obj.teacher_id != session['user_id'] or not session_obj.is_active:
        return '', 403
    
    totp = pyotp.TOTP(session_obj.secret_key)
    code = totp.now()
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(f"{session_id}:{code}")  # Encodes both for scan
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    os.makedirs('static/images', exist_ok=True)
    
    qr_filename = f'dynamic_qr_{session_id}.png'
    qr_path = os.path.join('static', 'images', qr_filename)
    try:
        img.save(qr_path)
        print(f"QR saved to: {qr_path}")  # Debug: Check terminal
    except Exception as e:
        print(f"QR save error: {e}")
        return '', 500
        
    return send_file(qr_path, mimetype='image/png')

@app.route('/get_attendees/<int:session_id>')
def get_attendees(session_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return '', 404  # Silent fail

    session_obj = Session.query.get_or_404(session_id)
    if session_obj.teacher_id != session['user_id']:
        return '', 404

    attendees = db.session.query(User.name, Attendance.scan_time).join(Attendance).filter(Attendance.session_id == session_id).order_by(Attendance.scan_time).all()
    return render_template('attendees_partial.html', attendees=attendees, session_id=session_id)

@app.route('/export_csv/<int:session_id>')
def export_csv(session_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return 'Access denied.', 403
    
    session_obj = Session.query.get_or_404(session_id)
    if session_obj.teacher_id != session['user_id']:
        return 'Not your session.', 403
    
    attendees = db.session.query(User.name, Attendance.scan_time).join(Attendance).filter(Attendance.session_id == session_id).order_by(Attendance.scan_time).all()
    
    from io import StringIO
    import csv
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Scan Time'])
    for attendee in attendees:
        writer.writerow([attendee.name, attendee.scan_time])
    
    return output.getvalue(), 200, {'Content-Type': 'text/csv', 'Content-Disposition': f'attachment; filename=attendance_{session_id}.csv'}

@app.route('/mark_attendance', methods=['POST'])
def mark_attendance():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Access denied. Students only.', 'error')
        return redirect(url_for('home'))

    qr_data = request.form['totp_code'].strip()  # "session_id:code"
    print(f"Debug: Received QR data: {qr_data}")  # NEW: Log for debug
    if ':' not in qr_data:
        flash('Invalid QR format. Scan again.', 'error')
        return redirect(url_for('scan_qr'))
    
    session_id_str, totp_code = qr_data.split(':', 1)
    try:
        session_id = int(session_id_str)
    except ValueError:
        flash('Invalid session ID in QR. Scan again.', 'error')
        return redirect(url_for('scan_qr'))
    
    session_obj = Session.query.get(session_id)
    if not session_obj:
        flash('No session found. Contact teacher.', 'error')
        return redirect(url_for('student_dashboard'))
    
    # Check expiry first (fast)
    if datetime.now() > session_obj.expires_at:
        flash('Session expired. Ask teacher for new QR.', 'error')
        return redirect(url_for('student_dashboard'))
    
    if not session_obj.is_active:
        flash('Session is no longer active.', 'error')
        return redirect(url_for('student_dashboard'))
    
    # Verify TOTP with more tolerance (90s window for scan delays)
    totp = pyotp.TOTP(session_obj.secret_key)
    print(f"Debug: Verifying code '{totp_code}' for session {session_id}")  # NEW: Log
    if not totp.verify(totp_code, valid_window=3):  # Increased to 3 (90s)
        flash('Invalid QR code. It changes every minute—scan again!', 'error')
        return redirect(url_for('scan_qr'))
    
    # Check duplicate
    existing = Attendance.query.filter_by(user_id=session['user_id'], session_id=session_id).first()
    if existing:
        flash('Attendance already marked for this session.', 'error')
        return redirect(url_for('student_dashboard'))

    # Mark
    new_attendance = Attendance(user_id=session['user_id'], session_id=session_id)
    db.session.add(new_attendance)
    db.session.commit()
    print(f"Debug: Marked attendance for user {session['user_id']} in session {session_id}")  # NEW: Success log
    flash(f'Attendance marked for {session_obj.subject.name} on {session_obj.date}! ✅', 'success')

    return redirect(url_for('student_dashboard'))

@app.route('/scan_qr')
def scan_qr():
    if 'user_id' not in session or session['role'] != 'student':
        flash('Access denied. Students only.', 'error')
        return redirect(url_for('home'))
    return render_template('scan_qr.html')

@app.route('/logout')
def logout():
    session.clear()  # Clears the login session
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)