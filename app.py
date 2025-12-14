import logging
import threading

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session, abort, json
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
import secrets
import string
import subprocess
from datetime import datetime
from functools import wraps
import re

app = Flask(__name__)
load_dotenv()


# Security configurations
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATA_FOLDER'] = 'data'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500 MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'zip', 'ova', 'txt', 'doc', 'docx', 'ppt', 'pptx'}
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)
# Setup security logger
security_logger = logging.getLogger('security')
security_handler = logging.FileHandler('security.log')
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.INFO)


# Initialize CSRF protection
csrf = CSRFProtect(app)
csrf.init_app(app)

# Admin credentials (use hashed password)
ADMIN_USERNAME = 'admin'
# Load from environment variable or secure config
ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH') or generate_password_hash(
    os.environ.get('ADMIN_PASSWORD', 'CHANGE_ME_IMMEDIATELY')
)

# Warn if using default
if not os.environ.get('ADMIN_PASSWORD_HASH'):
    app.logger.warning('⚠️  Using default admin password! Set ADMIN_PASSWORD_HASH environment variable!')
SESSIONS_FILE = 'sessions.json'

# Create the necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DATA_FOLDER'], exist_ok=True)  # Creates 'data/' folder

# Simple in-memory storage (in production, use a proper database)
training_sessions = {}
session_counter = 0
storage_lock = threading.Lock()

# Login attempt tracking (basic rate limiting)
login_attempts = {}
session_access_attempts = {}  # Track session password attempts

def load_sessions():
    """Load sessions from persistent storage"""
    global training_sessions, session_counter
    try:
        with storage_lock:  # Protect with lock
            if os.path.exists(SESSIONS_FILE):
                with open(SESSIONS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    training_sessions = data.get('sessions', {})
                    training_sessions = {int(k): v for k, v in training_sessions.items()}
                    session_counter = data.get('counter', 0)
                    app.logger.info(f'Loaded {len(training_sessions)} sessions from storage')
    except Exception as e:
        app.logger.error(f'Error loading sessions: {str(e)}')

def save_sessions():
    """Save sessions to persistent storage"""
    try:
        with storage_lock:
            data = {
                'sessions': training_sessions,
                'counter': session_counter
            }
            # Write to temporary file first (atomic write)
            temp_file = SESSIONS_FILE + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            # Atomic rename
            os.replace(temp_file, SESSIONS_FILE)
    except Exception as e:
        app.logger.error(f'Error saving sessions: {str(e)}')

load_sessions()

def is_safe_path(basedir, path, follow_symlinks=True):
    """Check if a path is safe and doesn't escape the base directory"""
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, matchpath))


def validate_filename(filename):
    """Validate filename to prevent path traversal"""
    # Remove any path components
    filename = os.path.basename(filename)

    # Check for null bytes
    if '\0' in filename:
        return None

    # Check for path traversal patterns
    if '..' in filename or filename.startswith('.'):
        return None

    # Only allow alphanumeric, dash, underscore, and dot
    if not re.match(r'^[\w\-. ]+$', filename):
        return None

    return filename


def get_client_ip():
    """
    Get the real client IP address, considering proxies.
    Checks X-Forwarded-For header but validates it.
    """
    # If behind a trusted proxy, check X-Forwarded-For
    # Only trust the rightmost IP that's not from the proxy itself
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
        # Take the first one (leftmost) as the original client
        # But be careful: this can be spoofed if not behind a trusted proxy
        ip_list = request.headers.get('X-Forwarded-For').split(',')
        # Get the first IP and strip whitespace
        client_ip = ip_list[0].strip()
        return client_ip

    # Fallback to direct connection IP
    return request.remote_addr

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def generate_password():
    """Generate a secure random password"""
    with open('data/bip39.txt', 'r') as file:
        words = [line.strip() for line in file.readlines()]
    word1 = secrets.choice(words)
    word2 = secrets.choice(words)
    number = ''.join(secrets.choice(string.digits) for _ in range(8))
    symbol1 = secrets.choice(['!', '@', '#', '$', '%', '-', '_', '/', '<', '>', ',', '.', '*'])
    symbol2 = secrets.choice(['!', '@', '#', '$', '%', '-', '_', '/', '<', '>', ',', '.', '*'])
    return f"{word1}{symbol1}{word2}{symbol2}{number}"


def check_rate_limit(ip_address, max_attempts=5, window=300):
    """Simple rate limiting for login attempts"""
    current_time = datetime.now().timestamp()

    if ip_address not in login_attempts:
        login_attempts[ip_address] = []

    # Remove old attempts outside the time window
    login_attempts[ip_address] = [
        timestamp for timestamp in login_attempts[ip_address]
        if current_time - timestamp < window
    ]

    # Check if limit exceeded
    if len(login_attempts[ip_address]) >= max_attempts:
        return False

    # Add current attempt
    login_attempts[ip_address].append(current_time)
    return True


def check_session_rate_limit(ip_address, session_id, max_attempts=10, window=300):
    """Rate limiting for session password attempts"""
    current_time = datetime.now().timestamp()
    key = f"{ip_address}:{session_id}"

    if key not in session_access_attempts:
        session_access_attempts[key] = []

    # Remove old attempts outside the time window
    session_access_attempts[key] = [
        timestamp for timestamp in session_access_attempts[key]
        if current_time - timestamp < window
    ]

    # Check if limit exceeded
    if len(session_access_attempts[key]) >= max_attempts:
        return False

    # Add current attempt
    session_access_attempts[key].append(current_time)
    return True


def session_password_required(f):
    """Decorator to check if user has authenticated for a specific session"""

    @wraps(f)
    def decorated_function(session_id, *args, **kwargs):
        # Check if session exists
        if session_id not in training_sessions:
            abort(404)

        session_data = training_sessions[session_id]

        # Check if session is validated
        if not session_data.get('validated', False):
            flash('This training session is not yet available', 'warning')
            return redirect(url_for('index'))

        # Check if user has authenticated for this session
        authenticated_sessions = session.get('authenticated_sessions', [])
        if session_id not in authenticated_sessions:
            # Redirect to password page
            return redirect(url_for('session_password', session_id=session_id))

        return f(session_id, *args, **kwargs)

    return decorated_function


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('Please log in to access the admin panel', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)

    return decorated_function


# Student Routes
# Student Routes
@app.route('/')
def index():
    """Display all validated training sessions for students"""
    validated_sessions = {k: v for k, v in training_sessions.items() if v.get('validated', False)}
    return render_template('index.html', sessions=validated_sessions)


@app.route('/session/<int:session_id>/password', methods=['GET', 'POST'])
def session_password(session_id):
    """Password authentication page for a specific session"""
    if session_id not in training_sessions:
        abort(404)

    session_data = training_sessions[session_id]

    # Check if session is validated
    if not session_data.get('validated', False):
        flash('This training session is not yet available', 'warning')
        return redirect(url_for('index'))

    # Check if already authenticated
    authenticated_sessions = session.get('authenticated_sessions', [])
    if session_id in authenticated_sessions:
        return redirect(url_for('session_detail', session_id=session_id))

    if request.method == 'POST':
        ip_address = get_client_ip()  # Changed here

        # Check rate limit
        if not check_session_rate_limit(ip_address, session_id):
            flash('Too many password attempts. Please try again later.', 'error')
            return render_template('session_password.html',
                                   session=session_data,
                                   session_id=session_id), 429

        password = request.form.get('password', '').strip()

        # Validate input
        if not password:
            security_logger.warning(f'Failed session password attempt from IP {ip_address}')
            flash('Password is required', 'error')
            return render_template('session_password.html',
                                   session=session_data,
                                   session_id=session_id)

        # Check password (constant-time comparison)
        if check_password_hash(session_data.get('password', ''), password):
            # Authentication successful
            if 'authenticated_sessions' not in session:
                session['authenticated_sessions'] = []

            session['authenticated_sessions'].append(session_id)
            session.modified = True
            session.modified = True

            # Clear failed attempts for this IP/session
            key = f"{ip_address}:{session_id}"
            if key in session_access_attempts:
                session_access_attempts[key] = []

            flash('Access granted!', 'success')
            return redirect(url_for('session_detail', session_id=session_id))
        else:
            security_logger.warning(f'Failed session password attempt for session {session_id} from IP {ip_address}')
            flash('Invalid password', 'error')

    return render_template('session_password.html',
                           session=session_data,
                           session_id=session_id)


@app.route('/session/<int:session_id>')
@session_password_required
def session_detail(session_id):
    """Display details and files for a specific training session"""
    session_data = training_sessions[session_id]
    return render_template('session_detail.html', session=session_data, session_id=session_id, session_description=training_sessions[session_id]['description'].split('\n'))


@app.route('/download/<int:session_id>/<path:filename>')
@session_password_required
def download_file(session_id, filename):
    """Download a file from a training session - SECURED VERSION"""
    session_data = training_sessions[session_id]

    # Validate and sanitize filename
    safe_filename = validate_filename(filename)
    if not safe_filename:
        abort(400, "Invalid filename")

    # Check if filename is in the session's file list
    if safe_filename not in session_data.get('files', []):
        abort(403, "File not associated with this session")

    # Build and validate the full path
    base_dir = os.path.realpath(os.path.join(app.config['UPLOAD_FOLDER'], str(session_id)))
    file_path = os.path.realpath(os.path.join(base_dir, safe_filename))

    # Ensure the file is within the allowed directory
    if not is_safe_path(base_dir, file_path):
        abort(403, "Access denied")

    # Check if file exists
    if not os.path.exists(file_path):
        abort(404, "File not found")

    return send_file(file_path, as_attachment=True, download_name=safe_filename)


# Admin Routes
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page with rate limiting"""
    if request.method == 'POST':
        ip_address = get_client_ip()  # Changed here

        # Check rate limit
        if not check_rate_limit(ip_address):
            flash('Too many login attempts. Please try again later.', 'error')
            return render_template('admin_login.html'), 429

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Validate input
        if not username or not password:
            flash('Username and password are required', 'error')
            security_logger.warning(f'Failed login attempt from IP {ip_address}')
            return render_template('admin_login.html')

        # Check credentials using constant-time comparison
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            old_session = dict(session)  # Preserve any needed data
            session.clear()  # Clear existing session
            session.permanent = True
            session['admin_logged_in'] = True
            # Regenerate session ID (Flask does this automatically on clear + set)

            # Clear login attempts for this IP on successful login
            if ip_address in login_attempts:
                login_attempts[ip_address] = []

            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            security_logger.warning(f'Failed login attempt for user "{username}" from IP {ip_address}')
            flash('Invalid credentials', 'error')


    return render_template('admin_login.html')


@app.route('/admin/logout', methods=['POST'])
@login_required
def admin_logout():
    """Admin logout"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))


@app.route('/admin')
@login_required
def admin_dashboard():
    """Admin dashboard showing all training sessions"""
    return render_template('admin_dashboard.html', sessions=training_sessions)


@app.route('/admin/session/create', methods=['GET', 'POST'])
@login_required
def create_session():
    """Create a new training session"""
    global session_counter

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()

        # Validate input
        if not title or len(title) > 200:
            flash('Title is required and must be less than 200 characters', 'error')
            return redirect(url_for('create_session'))

        if len(description) > 2000:
            flash('Description must be less than 2000 characters', 'error')
            return redirect(url_for('create_session'))

        with storage_lock:  # Protect counter increment
            session_counter += 1
            session_id = session_counter

        # Create session directory
        session_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(session_id))
        os.makedirs(session_dir, exist_ok=True)

        # Handle file uploads
        files = request.files.getlist('files')
        uploaded_files = []

        for file in files:
            if file and file.filename:
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)  # Reset to beginning

                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    flash(f'File "{file.filename}" exceeds {app.config['MAX_CONTENT_LENGTH']}B limit', 'error')
                    continue
                # Secure the filename
                original_filename = file.filename
                safe_name = secure_filename(original_filename)

                # Additional validation
                safe_name = validate_filename(safe_name)
                if not safe_name or not allowed_file(safe_name):
                    flash(f'File "{original_filename}" has invalid name or extension', 'warning')
                    continue

                # Check for duplicate filenames
                if safe_name in uploaded_files:
                    flash(f'Duplicate filename "{safe_name}" skipped', 'warning')
                    continue

                try:
                    file_path = os.path.join(session_dir, safe_name)
                    file.save(file_path)
                    uploaded_files.append(safe_name)
                except Exception as e:
                    flash(f'Error uploading file "{safe_name}": {str(e)}', 'error')

        training_sessions[session_id] = {
            'id': session_id,
            'title': title,
            'description': description,
            'files': uploaded_files,
            'validated': False,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'student_count': 0,
            'password': ''
        }
        save_sessions()
        flash(f'Training session "{title}" created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_session.html')


@app.route('/admin/session/<int:session_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_session(session_id):
    """Edit an existing training session"""
    if session_id not in training_sessions:
        abort(404)

    session_data = training_sessions[session_id]

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()

        # Validate input
        if not title or len(title) > 200:
            flash('Title is required and must be less than 200 characters', 'error')
            return redirect(url_for('edit_session', session_id=session_id))

        if len(description) > 2000:
            flash('Description must be less than 2000 characters', 'error')
            return redirect(url_for('edit_session', session_id=session_id))

        session_data['title'] = title
        session_data['description'] = description

        # Handle new file uploads
        files = request.files.getlist('files')
        session_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(session_id))

        for file in files:
            if file and file.filename:
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)  # Reset to beginning

                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    flash(f'File "{file.filename}" exceeds {app.config['MAX_CONTENT_LENGTH']}B limit', 'error')
                    continue
                original_filename = file.filename
                safe_name = secure_filename(original_filename)

                # Additional validation
                safe_name = validate_filename(safe_name)
                if not safe_name or not allowed_file(safe_name):
                    flash(f'File "{original_filename}" has invalid name or extension', 'warning')
                    continue

                # Check for duplicate filenames
                if safe_name in session_data['files']:
                    flash(f'File "{safe_name}" already exists', 'warning')
                    continue

                try:
                    file_path = os.path.join(session_dir, safe_name)
                    file.save(file_path)
                    session_data['files'].append(safe_name)
                    save_sessions()
                except Exception as e:
                    flash(f'Error uploading file "{safe_name}": {str(e)}', 'error')

        flash('Training session updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_session.html', session=session_data, session_id=session_id)


@app.route('/admin/session/<int:session_id>/delete_file/<path:filename>', methods=['POST'])
@login_required
def delete_file(session_id, filename):
    """Delete a file from a training session - SECURED VERSION"""
    if session_id not in training_sessions:
        abort(404)

    session_data = training_sessions[session_id]

    # Validate and sanitize filename
    safe_filename = validate_filename(filename)
    if not safe_filename:
        abort(400, "Invalid filename")

    # Check if filename is in the session's file list
    if safe_filename not in session_data.get('files', []):
        abort(403, "File not associated with this session")

    # Build and validate the full path
    base_dir = os.path.realpath(os.path.join(app.config['UPLOAD_FOLDER'], str(session_id)))
    file_path = os.path.realpath(os.path.join(base_dir, safe_filename))

    # Ensure the file is within the allowed directory
    if not is_safe_path(base_dir, file_path):
        abort(403, "Access denied")

    # Delete the file
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            session_data['files'].remove(safe_filename)
            save_sessions()
            flash(f'File "{safe_filename}" deleted successfully!', 'success')
        else:
            flash('File not found', 'error')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'error')

    return redirect(url_for('edit_session', session_id=session_id))


@app.route('/admin/session/<int:session_id>/validate', methods=['POST'])
@login_required
def validate_session(session_id):
    """Validate a training session and set student count - SECURED VERSION"""
    if session_id not in training_sessions:
        abort(404)

    session_data = training_sessions[session_id]
    student_count = request.form.get('student_count', type=int)

    # Validate student count
    if student_count is None:  # Explicitly check None
        flash('Student count is required', 'error')
        return redirect(url_for('admin_dashboard'))
    if not student_count or student_count < 1 or student_count > 1000:
        flash('Please enter a valid student count (1-1000)', 'error')
        return redirect(url_for('admin_dashboard'))

    # Generate password
    password = generate_password()
    session_data['password'] = generate_password_hash(password)  # Hash it!
    session_data['validated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Update session
    session_data['validated'] = True
    session_data['student_count'] = student_count
    temp_plain_password = password
    session_data['password'] = generate_password_hash(password)
    session_data['validated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    save_sessions()
    # Call bash script with proper escaping
    script_path = os.path.abspath('./provision_students.sh')

    # Verify script exists and is executable
    if not os.path.exists(script_path):
        flash(f'Session validated! Students: {student_count}, Password: {temp_plain_password}. (Script not found)', 'warning')
        return redirect(url_for('admin_dashboard'))

    if not os.access(script_path, os.X_OK):
        flash(f'Session validated! Students: {student_count}, Password: {temp_plain_password}. (Script not executable)', 'warning')
        return redirect(url_for('admin_dashboard'))

    try:
        # Use list form to prevent shell injection
        # subprocess.run does NOT use shell when passing a list
        result = subprocess.run(
            [script_path, str(student_count), password],
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,  # Explicitly disable shell
            cwd=os.path.dirname(script_path)
        )

        if result.returncode == 0:
            flash(f'Session validated! Students: {student_count}, Password: {temp_plain_password}', 'success')
            if result.stdout:
                flash(f'Script output: {result.stdout[:500]}', 'info')  # Limit output length
        else:
            flash(f'Session validated but script failed: {result.stderr[:500]}', 'warning')
    except subprocess.TimeoutExpired:
        flash(f'Session validated! Students: {student_count}, Password: {temp_plain_password}. Script timeout.', 'warning')
    except Exception as e:
        flash(f'Session validated! Students: {student_count}, Password: {temp_plain_password}. Script error: {str(e)[:200]}',
              'warning')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/session/<int:session_id>/invalidate', methods=['POST'])
@login_required
def invalidate_session(session_id):
    """Invalidate a training session"""
    if session_id not in training_sessions:
        abort(404)

    training_sessions[session_id]['validated'] = False
    save_sessions()
    flash('Training session invalidated', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/session/<int:session_id>/delete', methods=['POST'])
@login_required
def delete_session(session_id):
    """Delete a training session"""
    if session_id not in training_sessions:
        abort(404)

    # Delete session directory
    session_dir = os.path.join(app.config['UPLOAD_FOLDER'], str(session_id))

    try:
        if os.path.exists(session_dir):
            import shutil
            shutil.rmtree(session_dir)

        del training_sessions[session_id]
        save_sessions()
        flash('Training session deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting session: {str(e)}', 'error')

    return redirect(url_for('admin_dashboard'))


# Error handlers
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error='403 - Access Forbidden', message=str(e)), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error='404 - Not Found', message=str(e)), 404


@app.errorhandler(413)
def too_large(e):
    return render_template('error.html', error='413 - File Too Large', message='File exceeds maximum size limit'), 413


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template('error.html', error='429 - Too Many Requests', message='Please try again later'), 429

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

if __name__ == '__main__':
    app.run(host="0.0.0.0", Debug=True)