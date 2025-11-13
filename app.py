from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response, g
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, timedelta, timezone
import sqlite3
import os
import re
import secrets
import hashlib
from PIL import Image
import io
import pytz
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['DATABASE'] = 'mfqod.db'
app.config['POSTS_PER_PAGE'] = 10
app.config['MESSAGES_PER_PAGE'] = 50

# Timezone Configuration
UTC_TIMEZONE = pytz.UTC

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Create upload directories
UPLOAD_DIRS = ['avatars', 'posts', 'messages', 'website']
for directory in UPLOAD_DIRS:
    path = os.path.join(app.config['UPLOAD_FOLDER'], directory)
    os.makedirs(path, exist_ok=True)

# ==================== TIME UTILITIES ====================

def get_current_time():
    """Get current time in UTC"""
    return datetime.now(UTC_TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')

def get_utc_now():
    """Get current datetime object in UTC"""
    return datetime.now(UTC_TIMEZONE)

def get_local_time(dt_str):
    """Convert UTC string to local time string (for display)"""
    if not dt_str:
        return ""
    try:
        utc_dt = datetime.strptime(dt_str, '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.UTC)
        # Assuming local timezone is 'Asia/Baghdad' for example. This should be user-specific in a real app.
        local_tz = pytz.timezone('Asia/Baghdad') 
        local_dt = utc_dt.astimezone(local_tz)
        return local_dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Time conversion error: {e}")
        return dt_str
        
# ==================== DATABASE UTILITIES ====================

def get_db():
    """Get database connection (uses g for request-local connection)"""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    """Close database connection at the end of the request"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database"""
    with app.app_context():
        conn = get_db()
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                avatar TEXT,
                bio TEXT CHECK(length(bio) <= 50),
                phone TEXT,
                location TEXT,
                website TEXT,
                is_admin BOOLEAN DEFAULT 0,
                is_active BOOLEAN DEFAULT 1,
                email_verified BOOLEAN DEFAULT 0,
                verification_token TEXT,
                reset_token TEXT,
                reset_token_expiry TEXT,
                last_login TEXT,
                last_seen TEXT,
                is_online BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Posts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT,
                image TEXT,
                status TEXT DEFAULT 'not_found',
                section TEXT DEFAULT 'other',
                original_post_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (original_post_id) REFERENCES posts (id) ON DELETE CASCADE
            )
        ''')
        
        # Post likes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS post_likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(post_id, user_id)
            )
        ''')
        
        # Post comments
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS post_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Messages
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message TEXT,
                image TEXT,
                shared_post_id INTEGER,
                read BOOLEAN DEFAULT 0,
                edited BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (shared_post_id) REFERENCES posts (id) ON DELETE SET NULL
            )
        ''')
        
        # Message requests
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS message_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE,
                UNIQUE(sender_id, receiver_id)
            )
        ''')
        
        # Notifications
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                link TEXT,
                read BOOLEAN DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Activity logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                success INTEGER DEFAULT 1,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')

        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_user_id ON activity_log(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_log_created_at ON activity_log(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver_id ON messages(receiver_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)')

        conn.commit()
        print("✅ Database initialized!")

# ==================== AUTHENTICATION ====================

def login_required(f):
    """Decorator for routes that render HTML pages"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Login required to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ** NEW DECORATOR FOR API **
def api_login_required(f):
    """Decorator for API routes that return JSON"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required. Please log in.'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator for routes that require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Login required', 'warning')
            return redirect(url_for('login'))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            flash('Admin access required', 'error')
            return redirect(url_for('home'))
        
        return f(*args, **kwargs)
    return decorated_function

# ** NEW DECORATOR FOR ADMIN API ROUTES **
def api_admin_required(f):
    """Decorator for API routes that require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required.'}), 401
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            return jsonify({'success': False, 'message': 'Admin access required.'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user():
    """Inject current user into all templates"""
    return dict(user=get_current_user())

def get_current_user():
    """Get current user from session"""
    if 'user_id' not in session:
        return None
    
    try:
        # Use g.db which is managed by get_db() and close_db()
        cursor = get_db().cursor()
        cursor.execute('''
            SELECT id, name, email, avatar, bio, phone, location, website, 
                   is_admin, is_active, email_verified, created_at,
                   (SELECT COUNT(*) FROM notifications WHERE user_id = users.id AND read = 0) as unread_notifications
            FROM users 
            WHERE id = ?
        ''', (session['user_id'],))
        user = cursor.fetchone()
        
        if user:
            return dict(user)
        
        # Clear session if user not found in DB
        session.clear()
        return None
    except Exception as e:
        print(f"Error getting current user: {e}")
        session.clear()
        return None

def log_activity(user_id, action, success=True, details=None):
    """Log user activity"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        ip_address = request.remote_addr if request else '127.0.0.1'
        user_agent = request.headers.get('User-Agent', '')[:255] if request else 'Unknown'
        created_at = get_current_time()
        
        cursor.execute('''
            INSERT INTO activity_log (user_id, action, ip_address, user_agent, success, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, action, ip_address, user_agent, 1 if success else 0, details, created_at))
        
        conn.commit()
    except Exception as e:
        print(f"Activity log error: {e}")

def create_notification(user_id, notif_type, title, message, link=None):
    """Create a notification for a user"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        created_at = get_current_time()
        
        cursor.execute('''
            INSERT INTO notifications (user_id, type, title, message, link, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, notif_type, title, message, link, created_at))
        
        conn.commit()
        
        socketio.emit('new_notification', {
            'type': notif_type,
            'title': title,
            'message': message,
            'link': link,
            'created_at': created_at
        }, room=f'user_{user_id}')
        
    except Exception as e:
        print(f"Notification error: {e}")

# ==================== FILE UTILITIES ====================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def compress_image(image_data, max_size=(1200, 1200), quality=85):
    """Compress and convert image to JPEG"""
    try:
        img = Image.open(io.BytesIO(image_data))
        
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
            img = background
        
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=quality, optimize=True)
        output.seek(0)
        
        return output.read(), 'jpg'
    except Exception as e:
        print(f"Image compression error: {e}")
        return image_data, 'png' # Fallback

def save_upload_file(file, upload_type='posts', compress=True):
    """Save uploaded file securely"""
    if not file or file.filename == '':
        return None
    
    if not allowed_file(file.filename):
        return None
    
    try:
        # Secure the filename
        original_filename = secure_filename(file.filename)
        ext = original_filename.rsplit('.', 1)[1].lower()
        
        file_data = file.read()
        
        if compress and ext in {'jpg', 'jpeg', 'png'}:
            file_data, new_ext = compress_image(file_data)
            ext = new_ext
        
        # Create a unique filename
        filename = f"{secrets.token_hex(16)}.{ext}"
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], upload_type, filename)
        with open(filepath, 'wb') as f:
            f.write(file_data)
        
        # Return relative path for use in templates
        return f"{upload_type}/{filename}"
        
    except Exception as e:
        print(f"File save error: {e}")
        return None

def delete_file(filename):
    """Delete file from upload folder"""
    try:
        if filename:
            # Filename already includes the subfolder (e.g., 'avatars/...')
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
    except Exception as e:
        print(f"File delete error: {e}")

# ==================== EMAIL UTILITIES (STUB) ====================

def send_password_reset_email(user_email, token):
    """
    (STUB FUNCTION)
    This function should send an email with the password reset link.
    Replace this with your actual email sending logic (e.g., Flask-Mail, SendGrid, Mailgun).
    """
    reset_link = url_for('reset_password', token=token, _external=True)
    
    print("="*50)
    print("PASSWORD RESET (STUB)")
    print(f"To: {user_email}")
    print(f"Subject: Reset Your Password")
    print("Body: Please click the link below to reset your password.")
    print(f"Link: {reset_link}")
    print("="*50)
    
# ==================== ROUTES ====================

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # This route now only handles API requests, but we'll leave
        # the POST logic in case of non-JS form submission
        try:
            name = request.form.get('name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not name or not email or not password:
                flash('All fields are required', 'error')
                return render_template('register.html')
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                flash('Email already registered', 'error')
                return render_template('register.html')
            
            hashed_password = generate_password_hash(password)
            created_at = get_current_time()
            
            cursor.execute('''
                INSERT INTO users (name, email, password, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, email, hashed_password, created_at, created_at))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            log_activity(user_id, 'Registration', True)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"Registration error: {e}")
            flash('Registration failed, please try again.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')




@app.route('/api/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not name or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        # --- (FIX 1) التحقق من صيغة البريد الإلكتروني على الخادم ---
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400

        # --- (FIX 2) التحقق من قوة كلمة المرور على الخادم (مطابق لملف register.html) ---
        if len(password) < 6 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters and include an uppercase letter, a lowercase letter, and a number.'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            # --- (FIX 3) تم حذف conn.close() ---
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        hashed_password = generate_password_hash(password)
        created_at = get_current_time()
        
        cursor.execute('''
            INSERT INTO users (name, email, password, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (name, email, hashed_password, created_at, created_at))
        
        user_id = cursor.lastrowid
        conn.commit()
        # --- (FIX 3) تم حذف conn.close() ---
        
        log_activity(user_id, 'Registration', True)
        
        return jsonify({'success': True, 'message': 'Registration successful!'})
        
    except Exception as e:
        print(f"API Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    user_id = session.get('user_id')
    if user_id:
        log_activity(user_id, 'User logged out', True)
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            
            if not email or not password:
                flash('Email and password are required', 'error')
                return render_template('login.html'), 400
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            
            if not user or not check_password_hash(user['password'], password):
                log_activity(None, 'Login Failed', False, f'Attempt for email: {email}')
                flash('Invalid email or password', 'error')
                return render_template('login.html'), 401
            
            if not user['is_active']:
                log_activity(user['id'], 'Login Failed', False, 'Account deactivated')
                flash('Your account is deactivated. Please contact support.', 'error')
                return render_template('login.html'), 403
            
            last_login = get_current_time()
            cursor.execute('UPDATE users SET last_login = ?, is_online = 1 WHERE id = ?', (last_login, user['id']))
            conn.commit()
            
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['is_admin'] = user['is_admin']
            
            log_activity(user['id'], 'Login', True)
            
            # Handle JSON response for fetch request
            if request.headers.get('Content-Type') == 'application/x-www-form-urlencoded':
                 return jsonify({'success': True, 'message': f'Welcome back, {user["name"]}!', 'redirect': url_for('home')})

            flash(f'Welcome back, {user["name"]}!', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            print(f"Login error: {e}")
            flash('Login failed due to a server error', 'error')
            return render_template('login.html'), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    
    if user_id:
        try:
            conn = get_db()
            cursor = conn.cursor()
            last_seen = get_current_time()
            cursor.execute('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?', (last_seen, user_id))
            conn.commit()
            
            log_activity(user_id, 'Logout', True)
        except Exception as e:
            print(f"Logout update error: {e}")
    
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET'])
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET'])
def reset_password(token):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, reset_token_expiry FROM users WHERE reset_token = ?', (token,))
        user = cursor.fetchone()
        
        if not user:
            flash('Invalid or expired password reset link.', 'error')
            return redirect(url_for('login'))
        
        expiry_time = datetime.strptime(user['reset_token_expiry'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC_TIMEZONE)
        
        if get_utc_now() > expiry_time:
            flash('Password reset link has expired. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))
        
        return render_template('reset_password.html', token=token)
        
    except Exception as e:
        print(f"Reset password page error: {e}")
        flash('An error occurred.', 'error')
        return redirect(url_for('login'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    return render_template('admin.html', is_guest=False)

@app.route('/home')
def home():
    user = get_current_user()
    is_guest = user is None
    
    return render_template('home.html', 
                         is_guest=is_guest,
                         today=get_utc_now().strftime('%Y-%m-%d'),
                         yesterday=(get_utc_now() - timedelta(days=1)).strftime('%Y-%m-%d'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) as count FROM posts WHERE user_id = ?', (user['id'],))
    posts_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM post_likes WHERE user_id = ?', (user['id'],))
    likes_given = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT COUNT(*) as count 
        FROM post_likes 
        WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)
    ''', (user['id'],))
    likes_received = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM post_comments WHERE user_id = ?', (user['id'],))
    comments_count = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT action, created_at, success
        FROM activity_log
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 10
    ''', (user['id'],))
    recent_activity = [dict(row) for row in cursor.fetchall()]
    
    stats = {
        'posts': posts_count,
        'likes_given': likes_given,
        'likes_received': likes_received,
        'comments': comments_count
    }
    
    return render_template('dashboard.html', 
                         stats=stats,
                         recent_activity=recent_activity)

@app.route('/users')
def users():
    user = get_current_user()
    is_guest = user is None
    
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    per_page = 12
    
    conn = get_db()
    cursor = conn.cursor()
    
    base_query = 'FROM users'
    where_clause = ''
    params = []
    
    if search:
        where_clause = "WHERE name LIKE ? OR email LIKE ?"
        search_pattern = f'%{search}%'
        params = [search_pattern, search_pattern]
    
    # *** SECURITY FIX: Parameterized query for count ***
    cursor.execute(f'SELECT COUNT(*) as count {base_query} {where_clause}', params)
    total = cursor.fetchone()['count']
    
    offset = (page - 1) * per_page
    query_params = params + [per_page, offset]
    
    # *** SECURITY FIX: Parameterized query for select ***
    cursor.execute(f'''
        SELECT id, name, email, avatar, bio, is_admin, email_verified, 
               created_at, is_online, last_seen, location
        {base_query}
        {where_clause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    ''', query_params)
    
    users_list = [dict(row) for row in cursor.fetchall()]
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('users.html', 
                         is_guest=is_guest,
                         users=users_list,
                         page=page,
                         total_pages=total_pages,
                         total=total,
                         search=search)

@app.route('/messages')
@login_required
def messages():
    user = get_current_user()
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get conversations with last message
        cursor.execute('''
            SELECT 
                u.id as other_user_id,
                u.name as other_user_name,
                u.avatar as other_user_avatar,
                u.is_online as other_user_online,
                MAX(m.created_at) as last_message_time
            FROM messages m
            JOIN users u ON u.id = CASE 
                                    WHEN m.sender_id = ? THEN m.receiver_id 
                                    ELSE m.sender_id 
                                END
            WHERE m.sender_id = ? OR m.receiver_id = ?
            GROUP BY u.id, u.name, u.avatar, u.is_online
            ORDER BY last_message_time DESC
        ''', (user['id'], user['id'], user['id']))
        
        conversations = [dict(row) for row in cursor.fetchall()]
        
        for convo in conversations:
            # Get last message content
            cursor.execute('''
                SELECT message, image
                FROM messages
                WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
                  AND created_at = ?
                LIMIT 1
            ''', (user['id'], convo['other_user_id'], convo['other_user_id'], user['id'], convo['last_message_time']))
            
            last_message = cursor.fetchone()
            if last_message:
                if last_message['image']:
                    convo['last_message'] = "[Image]"
                else:
                    convo['last_message'] = last_message['message']
            else:
                convo['last_message'] = "..."

            # Get unread count
            cursor.execute('''
                SELECT COUNT(*) as count
                FROM messages
                WHERE sender_id = ? AND receiver_id = ? AND read = 0
            ''', (convo['other_user_id'], user['id']))
            
            convo['unread_count'] = cursor.fetchone()['count']
        
        cursor.execute('''
            SELECT 
                mr.id, mr.sender_id, mr.created_at,
                u.name as sender_name, u.avatar as sender_avatar
            FROM message_requests mr
            JOIN users u ON mr.sender_id = u.id
            WHERE mr.receiver_id = ? AND mr.status = 'pending'
            ORDER BY mr.created_at DESC
        ''', (user['id'],))
        
        pending_requests = [dict(row) for row in cursor.fetchall()]
        
        return render_template('messages.html', 
                             conversations=conversations,
                             pending_requests=pending_requests)
        
    except Exception as e:
        print(f"Messages error: {e}")
        import traceback
        traceback.print_exc()
        
        flash('Failed to load messages', 'error')
        return redirect(url_for('home'))

@app.route('/chat/<int:other_user_id>')
@login_required
def chat(other_user_id):
    user = get_current_user()
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get other user info
    cursor.execute('SELECT id, name, email, avatar, is_online, last_seen FROM users WHERE id = ?', (other_user_id,))
    other_user_row = cursor.fetchone()
    
    if not other_user_row:
        flash('User not found', 'error')
        return redirect(url_for('messages'))
    
    other_user = dict(other_user_row)
    
    # Check if conversation is allowed (message request accepted)
    has_permission = False
    request_status = None
    
    cursor.execute('''
        SELECT * FROM message_requests
        WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
        ORDER BY created_at DESC
        LIMIT 1
    ''', (user['id'], other_user_id, other_user_id, user['id']))
    
    request_result = cursor.fetchone()
    
    if request_result:
        request_status = dict(request_result)
        if request_status['status'] == 'accepted':
            has_permission = True
    
    # Get messages if permission exists
    messages = []
    if has_permission:
        cursor.execute('''
            SELECT 
                m.id, m.sender_id, m.receiver_id, m.message as content, 
                m.image as media_url, m.read, m.created_at, m.shared_post_id
            FROM messages m
            WHERE ((m.sender_id = ? AND m.receiver_id = ?) 
               OR (m.sender_id = ? AND m.receiver_id = ?))
            ORDER BY m.created_at ASC
        ''', (user['id'], other_user_id, other_user_id, user['id']))
        
        messages_rows = cursor.fetchall()
        
        # ** FIX: Add shared_post_data to messages **
        for row in messages_rows:
            msg = dict(row)
            if msg['shared_post_id']:
                cursor.execute('''
                    SELECT 
                        p.id, p.content, p.image,
                        u.name as user_name, u.avatar as user_avatar
                    FROM posts p
                    JOIN users u ON p.user_id = u.id
                    WHERE p.id = ?
                ''', (msg['shared_post_id'],))
                post_data = cursor.fetchone()
                msg['post_data'] = dict(post_data) if post_data else None
            else:
                msg['post_data'] = None
            messages.append(msg)
        
        # Mark messages as read
        cursor.execute('''
            UPDATE messages 
            SET read = 1 
            WHERE sender_id = ? AND receiver_id = ? AND read = 0
        ''', (other_user_id, user['id']))
        
        conn.commit()
    
    # *** BUG FIX: Add today and yesterday for the template ***
    today = get_utc_now().strftime('%Y-%m-%d')
    yesterday = (get_utc_now() - timedelta(days=1)).strftime('%Y-%m-%d')
    
    return render_template('chat.html', 
                         is_guest=False,
                         other_user=other_user,
                         has_permission=has_permission,
                         request_status=request_status,
                         messages=messages,
                         today=today,
                         yesterday=yesterday)

@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    return redirect(url_for('user_profile', user_id=user['id']))

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    current_user = get_current_user()
    is_guest = current_user is None
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, name, email, avatar, bio, phone, location, website,
               is_admin, email_verified, created_at, is_online, last_seen
        FROM users 
        WHERE id = ?
    ''', (user_id,))
    profile_user_row = cursor.fetchone()
    
    if not profile_user_row:
        flash('User not found', 'error')
        return redirect(url_for('home'))
    
    profile_user = dict(profile_user_row)
    
    cursor.execute('''
        SELECT 
            p.id, p.user_id, p.content, p.image, p.status, p.section, 
            p.created_at,
            (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) as likes_count,
            (SELECT COUNT(*) FROM post_comments WHERE post_id = p.id) as comments_count
        FROM posts p
        WHERE p.user_id = ?
        ORDER BY p.created_at DESC
        LIMIT 20
    ''', (user_id,))
    
    posts = [dict(row) for row in cursor.fetchall()]
    
    cursor.execute('SELECT COUNT(*) as count FROM posts WHERE user_id = ?', (user_id,))
    posts_count = cursor.fetchone()['count']
    
    cursor.execute('''
        SELECT COUNT(*) as count 
        FROM post_likes 
        WHERE post_id IN (SELECT id FROM posts WHERE user_id = ?)
    ''', (user_id,))
    likes_count = cursor.fetchone()['count']
    
    is_own_profile = current_user and current_user['id'] == user_id
    
    return render_template('profile.html',
                         is_guest=is_guest,
                         profile_user=profile_user,
                         posts=posts,
                         posts_count=posts_count,
                         likes_count=likes_count,
                         is_own_profile=is_own_profile)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/notifications')
@login_required
def notifications():
    user = get_current_user()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT * FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 50
    ''', (user['id'],))
    
    notifications_list = [dict(row) for row in cursor.fetchall()]
    
    return render_template('notifications.html', 
                         notifications=notifications_list)

# ==================== API ROUTES ====================

@app.route('/api/user')
@api_login_required
def api_get_user():
    user = get_current_user()
    return jsonify({'success': True, 'user': user})

@app.route('/api/get-posts', methods=['GET'])
def api_get_posts():
    user_id_to_check = session.get('user_id', -1)
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '').strip()
    section_filter = request.args.get('section', '').strip()
    per_page = app.config['POSTS_PER_PAGE']
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append("(p.content LIKE ? OR u.name LIKE ?)")
            search_pattern = f'%{search}%'
            params.extend([search_pattern, search_pattern])
        
        if status_filter and status_filter in ['not_found', 'found']:
            where_clauses.append("p.status = ?")
            params.append(status_filter)
        
        if section_filter and section_filter in ['animals', 'cards', 'bags', 'electronics', 'keys', 'jewelry', 'documents', 'other']:
            where_clauses.append("p.section = ?")
            params.append(section_filter)
        
        where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        # *** SECURITY FIX: Parameterized query for count ***
        cursor.execute(f'''
            SELECT COUNT(*) as count
            FROM posts p
            JOIN users u ON p.user_id = u.id
            {where_sql}
        ''', params)
        total = cursor.fetchone()['count']
        
        query_params = [user_id_to_check] + params + [per_page, (page - 1) * per_page]
        
        # *** SECURITY FIX: Parameterized query for select ***
        query = f'''
            SELECT 
                p.id, p.user_id, p.content, p.image, p.status, p.section, p.created_at,
                p.original_post_id,
                u.name as user_name, u.avatar as user_avatar,
                (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) as likes_count,
                (SELECT COUNT(*) FROM post_comments WHERE post_id = p.id) as comments_count,
                (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id AND user_id = ?) as user_liked,
                op.id as original_id, op.content as original_content, op.image as original_image,
                ou.name as original_user_name, ou.avatar as original_user_avatar
            FROM posts p
            JOIN users u ON p.user_id = u.id
            LEFT JOIN posts op ON p.original_post_id = op.id
            LEFT JOIN users ou ON op.user_id = ou.id
            {where_sql}
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        '''
        
        cursor.execute(query, query_params)
        
        posts = []
        for row in cursor.fetchall():
            post = dict(row)
            post['user_liked'] = bool(post['user_liked'])
            
            cursor.execute('''
                SELECT 
                    c.id, c.user_id, c.content, c.created_at,
                    u.name as user_name, u.avatar as user_avatar
                FROM post_comments c
                JOIN users u ON c.user_id = u.id
                WHERE c.post_id = ?
                ORDER BY c.created_at ASC
            ''', (post['id'],))
            
            post['comments'] = [dict(comment) for comment in cursor.fetchall()]
            posts.append(post)
        
        total_pages = (total + per_page - 1) // per_page
        
        return jsonify({
            'success': True, 
            'posts': posts,
            'page': page,
            'total_pages': total_pages,
            'total': total
        })
        
    except Exception as e:
        print(f"Get posts error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to fetch posts'}), 500

@app.route('/api/create-post', methods=['POST'])
@api_login_required
def create_post():
    try:
        user = get_current_user()
        
        content = request.form.get('content', '').strip()
        status = request.form.get('status', 'not_found')
        section = request.form.get('section', 'other')
        
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                image_filename = save_upload_file(file, 'posts', compress=True)
        
        if not content and not image_filename:
            return jsonify({'success': False, 'message': 'Content or image is required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        created_at = get_current_time()
        
        cursor.execute('''
            INSERT INTO posts (user_id, content, image, status, section, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user['id'], content, image_filename, status, section, created_at, created_at))
        
        post_id = cursor.lastrowid
        conn.commit()
        
        log_activity(user['id'], 'Post Created', True, f'Post ID: {post_id}')
        
        return jsonify({'success': True, 'message': 'Post created', 'post_id': post_id})
        
    except Exception as e:
        print(f"Create post error: {e}")
        return jsonify({'success': False, 'message': 'Failed to create post'}), 500

@app.route('/api/edit-post/<int:post_id>', methods=['POST', 'PUT']) # Allow PUT
@api_login_required
def edit_post(post_id):
    try:
        user = get_current_user()
        
        content = request.form.get('content', '').strip()
        status = request.form.get('status', 'not_found')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id, image FROM posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            return jsonify({'success': False, 'message': 'Post not found'}), 404
        
        if post['user_id'] != user['id'] and not user.get('is_admin'):
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        image_filename = post['image']
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                # Delete old image
                if image_filename:
                    delete_file(image_filename)
                # Save new one
                image_filename = save_upload_file(file, 'posts', compress=True)

        if not content and not image_filename:
             return jsonify({'success': False, 'message': 'Content or image is required'}), 400

        updated_at = get_current_time()
        cursor.execute('''
            UPDATE posts 
            SET content = ?, status = ?, image = ?, updated_at = ?
            WHERE id = ?
        ''', (content, status, image_filename, updated_at, post_id))
        
        conn.commit()
        
        log_activity(user['id'], 'Post Edited', True, f'Post ID: {post_id}')
        
        return jsonify({'success': True, 'message': 'Post updated successfully'})
        
    except Exception as e:
        print(f"Edit post error: {e}")
        return jsonify({'success': False, 'message': 'Failed to edit post'}), 500

@app.route('/api/delete-post/<int:post_id>', methods=['DELETE'])
@api_login_required
def delete_post(post_id):
    try:
        user = get_current_user()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id, image FROM posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            return jsonify({'success': False, 'message': 'Post not found'}), 404
        
        if post['user_id'] != user['id'] and not user.get('is_admin'):
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        if post['image']:
            delete_file(post['image'])
        
        cursor.execute('DELETE FROM posts WHERE id = ?', (post_id,))
        conn.commit()
        
        log_activity(user['id'], 'Post Deleted', True, f'Post ID: {post_id}')
        
        socketio.emit('post_deleted', {'post_id': post_id}, broadcast=True)
        
        return jsonify({'success': True, 'message': 'Post deleted successfully'})
        
    except Exception as e:
        print(f"Delete post error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to delete post'}), 500

@app.route('/api/toggle-like/<int:post_id>', methods=['POST'])
@api_login_required
def toggle_like(post_id):
    try:
        user = get_current_user()
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT user_id FROM posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            return jsonify({'success': False, 'message': 'Post not found'}), 404
        
        cursor.execute('SELECT id FROM post_likes WHERE post_id = ? AND user_id = ?', (post_id, user['id']))
        existing_like = cursor.fetchone()
        
        if existing_like:
            cursor.execute('DELETE FROM post_likes WHERE id = ?', (existing_like['id'],))
            action = 'unliked'
        else:
            created_at = get_current_time()
            cursor.execute('INSERT INTO post_likes (post_id, user_id, created_at) VALUES (?, ?, ?)', 
                          (post_id, user['id'], created_at))
            action = 'liked'
            
            if post['user_id'] != user['id']:
                create_notification(post['user_id'], 'like', '❤️ New Like', f'{user["name"]} liked your post', f'/home#post-{post_id}')
        
        conn.commit()
        
        cursor.execute('SELECT COUNT(*) as count FROM post_likes WHERE post_id = ?', (post_id,))
        likes_count = cursor.fetchone()['count']

        return jsonify({'success': True, 'action': action, 'likes_count': likes_count})
        
    except Exception as e:
        print(f"Toggle like error: {e}")
        return jsonify({'success': False, 'message': 'Failed'}), 500

@app.route('/api/add-comment', methods=['POST'])
@api_login_required
def add_comment():
    try:
        user = get_current_user()
        data = request.get_json()
        
        post_id = data.get('post_id')
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'success': False, 'message': 'Content is required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT user_id FROM posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            return jsonify({'success': False, 'message': 'Post not found'}), 404
        
        created_at = get_current_time()
        cursor.execute('INSERT INTO post_comments (post_id, user_id, content, created_at) VALUES (?, ?, ?, ?)',
                      (post_id, user['id'], content, created_at))
        
        comment_id = cursor.lastrowid
        conn.commit()
        
        if post['user_id'] != user['id']:
            create_notification(post['user_id'], 'comment', '💬 New Comment', f'{user["name"]} commented on your post', f'/home#post-{post_id}')
        
        comment_data = {
            'id': comment_id,
            'user_id': user['id'],
            'content': content,
            'created_at': created_at,
            'user_name': user['name'],
            'user_avatar': user['avatar']
        }

        return jsonify({'success': True, 'message': 'Comment added', 'comment': comment_data})
        
    except Exception as e:
        print(f"Add comment error: {e}")
        return jsonify({'success': False, 'message': 'Failed to add comment'}), 500

@app.route('/api/delete-comment/<int:comment_id>', methods=['DELETE'])
@api_login_required
def delete_comment(comment_id):
    try:
        user = get_current_user()
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if user owns the comment OR owns the post the comment is on (OR is admin)
        cursor.execute('''
            SELECT c.user_id as comment_owner_id, p.user_id as post_owner_id
            FROM post_comments c
            JOIN posts p ON c.post_id = p.id
            WHERE c.id = ?
        ''', (comment_id,))
        comment = cursor.fetchone()
        
        if not comment:
            return jsonify({'success': False, 'message': 'Comment not found'}), 404
        
        if (comment['comment_owner_id'] != user['id'] and 
            comment['post_owner_id'] != user['id'] and 
            not user.get('is_admin')):
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        cursor.execute('DELETE FROM post_comments WHERE id = ?', (comment_id,))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Comment deleted'})
        
    except Exception as e:
        print(f"Delete comment error: {e}")
        return jsonify({'success': False, 'message': 'Failed to delete comment'}), 500

@app.route('/api/repost/<int:post_id>', methods=['POST'])
@api_login_required
def repost(post_id):
    try:
        user = get_current_user()
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Find the original post, even if post_id is already a repost
        cursor.execute('SELECT original_post_id, user_id FROM posts WHERE id = ?', (post_id,))
        original_post = cursor.fetchone()
        
        if not original_post:
            return jsonify({'success': False, 'message': 'Post not found'}), 404
            
        original_post_id = original_post['original_post_id'] or post_id
        original_poster_id = original_post['user_id']
        
        if original_poster_id == user['id']:
            return jsonify({'success': False, 'message': 'You cannot repost your own post'}), 400
        
        cursor.execute('SELECT id FROM posts WHERE user_id = ? AND original_post_id = ?', (user['id'], original_post_id))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'You have already reposted this'}), 400
        
        # Get data from original post to copy
        cursor.execute('SELECT content, image, status, section FROM posts WHERE id = ?', (original_post_id,))
        post_to_copy = cursor.fetchone()

        created_at = get_current_time()
        cursor.execute('''
            INSERT INTO posts (user_id, content, image, status, section, original_post_id, created_at, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user['id'], post_to_copy['content'], post_to_copy['image'], post_to_copy['status'], post_to_copy['section'],
              original_post_id, created_at, created_at))
        
        new_post_id = cursor.lastrowid
        conn.commit()
        
        # Notify the original poster
        cursor.execute('SELECT user_id FROM posts WHERE id = ?', (original_post_id,))
        original_poster = cursor.fetchone()
        if original_poster and original_poster['user_id'] != user['id']:
            create_notification(original_poster['user_id'], 'repost', '🔄 New Repost', f'{user["name"]} reposted your post', f'/home#post-{new_post_id}')
        
        return jsonify({'success': True, 'message': 'Post reposted successfully'})
        
    except Exception as e:
        print(f"Repost error: {e}")
        return jsonify({'success': False, 'message': 'Failed to repost'}), 500

@app.route('/api/update-profile', methods=['POST'])
@api_login_required
def update_profile():
    try:
        user = get_current_user()
        
        name = request.form.get('name', user['name']).strip()
        bio = request.form.get('bio', user['bio'] or '').strip()
        phone = request.form.get('phone', user['phone'] or '').strip()
        location = request.form.get('location', user['location'] or '').strip()
        website = request.form.get('website', user['website'] or '').strip()
        remove_avatar = request.form.get('remove_avatar') == 'true'
        
        conn = get_db()
        cursor = conn.cursor()
        
        avatar_filename = user['avatar']
        
        if remove_avatar:
            if avatar_filename:
                delete_file(avatar_filename)
            avatar_filename = None
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename:
                if avatar_filename:
                    delete_file(avatar_filename)
                
                avatar_filename = save_upload_file(file, 'avatars', compress=True)
                
                if not avatar_filename:
                    return jsonify({'success': False, 'message': 'Invalid image file or upload failed'}), 400
        
        if not name or len(name) < 2:
            return jsonify({'success': False, 'message': 'Name must be at least 2 characters'}), 400
        
        if len(bio) > 50:
             return jsonify({'success': False, 'message': 'Bio must be 50 characters or less'}), 400
        
        if website and not (website.startswith('http://') or website.startswith('https://')):
            website = 'https://' + website
        
        updated_at = get_current_time()
        
        cursor.execute('''
            UPDATE users 
            SET name = ?, bio = ?, phone = ?, location = ?, website = ?, avatar = ?, updated_at = ?
            WHERE id = ?
        ''', (name, bio, phone, location, website, avatar_filename, updated_at, user['id']))
        
        conn.commit()
        
        session['user_name'] = name # Update session
        
        log_activity(user['id'], 'Profile Updated', True)
        
        return jsonify({
            'success': True, 
            'message': 'Profile updated successfully',
            'avatar_url': f"/static/uploads/{avatar_filename}" if avatar_filename else None,
            'user_initial': name[0].upper()
        })
        
    except Exception as e:
        print(f"Update profile error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to update profile'}), 500

@app.route('/api/change-password', methods=['POST'])
@api_login_required
def change_password():
    try:
        user = get_current_user()
        data = request.get_json()
        
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'New password must be at least 8 characters'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE id = ?', (user['id'],))
        user_data = cursor.fetchone()
        
        if not check_password_hash(user_data['password'], current_password):
            log_activity(user['id'], 'Password Change Failed', False, 'Incorrect current password')
            return jsonify({'success': False, 'message': 'Current password is incorrect'}), 400
        
        hashed_password = generate_password_hash(new_password)
        updated_at = get_current_time()
        cursor.execute('UPDATE users SET password = ?, updated_at = ? WHERE id = ?', 
                      (hashed_password, updated_at, user['id']))
        
        conn.commit()
        
        log_activity(user['id'], 'Password Changed', True)
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
        
    except Exception as e:
        print(f"Change password error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to change password'}), 500

@app.route('/api/delete-account', methods=['DELETE'])
@api_login_required
def delete_account():
    try:
        user = get_current_user()
        user_id = user['id']
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT avatar FROM users WHERE id = ?', (user_id,))
        user_data = cursor.fetchone()
        
        cursor.execute('SELECT image FROM posts WHERE user_id = ?', (user_id,))
        post_images = cursor.fetchall()
        
        cursor.execute('SELECT image FROM messages WHERE sender_id = ?', (user_id,))
        message_images = cursor.fetchall()

        if user_data['avatar']:
            delete_file(user_data['avatar'])
        
        for post in post_images:
            if post['image']:
                delete_file(post['image'])
        
        for msg in message_images:
            if msg['image']:
                delete_file(msg['image'])

        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        conn.commit()
        
        session.clear()
        
        log_activity(user_id, 'Account Deleted', True)
        
        return jsonify({'success': True, 'message': 'Account deleted successfully'})
        
    except Exception as e:
        print(f"Delete account error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to delete account'}), 500

@app.route('/api/message-request/<int:receiver_id>', methods=['POST'])
@api_login_required
def send_message_request(receiver_id):
    try:
        user = get_current_user()
        
        if user['id'] == receiver_id:
            return jsonify({'success': False, 'message': 'You cannot send a message request to yourself'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, name FROM users WHERE id = ?', (receiver_id,))
        receiver = cursor.fetchone()
        
        if not receiver:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        cursor.execute('''
            SELECT * FROM message_requests
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ''', (user['id'], receiver_id, receiver_id, user['id']))
        
        existing_request = cursor.fetchone()
        
        if existing_request:
            if existing_request['status'] == 'accepted':
                return jsonify({
                    'success': True, 
                    'message': f'You can already chat with {receiver["name"]}',
                    'redirect': url_for('chat', other_user_id=receiver_id)
                })
            elif existing_request['status'] == 'pending':
                if existing_request['sender_id'] == receiver_id:
                    # The other user already sent a request, so accept it
                    updated_at = get_current_time()
                    cursor.execute('''
                        UPDATE message_requests 
                        SET status = 'accepted', updated_at = ? 
                        WHERE id = ?
                    ''', (updated_at, existing_request['id']))
                    conn.commit()
                    
                    create_notification(receiver_id, 'message_request_accepted', '✅ Request Accepted',
                                      f'{user["name"]} accepted your message request', url_for('chat', other_user_id=user["id"]))
                    
                    return jsonify({
                        'success': True, 
                        'message': f'Request accepted! You can now chat with {receiver["name"]}',
                        'redirect': url_for('chat', other_user_id=receiver_id)
                    })
                else:
                    return jsonify({
                        'success': False, 
                        'message': 'You already sent a request. Waiting for response.'
                    }), 400
            elif existing_request['status'] == 'declined':
                # Allow re-sending a request if it was declined
                updated_at = get_current_time()
                cursor.execute('''
                    UPDATE message_requests 
                    SET status = 'pending', sender_id = ?, receiver_id = ?, updated_at = ? 
                    WHERE id = ?
                ''', (user['id'], receiver_id, updated_at, existing_request['id']))
        else:
            # No previous request, create a new one
            created_at = get_current_time()
            cursor.execute('''
                INSERT INTO message_requests (sender_id, receiver_id, status, created_at, updated_at)
                VALUES (?, ?, 'pending', ?, ?)
            ''', (user['id'], receiver_id, created_at, created_at))
        
        conn.commit()
        
        create_notification(receiver_id, 'message_request', '📨 New Message Request', 
                          f'{user["name"]} wants to message you', url_for('messages'))
        
        return jsonify({'success': True, 'message': 'Message request sent successfully'})
        
    except Exception as e:
        print(f"Message request error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to send message request'}), 500

@app.route('/api/message-request/respond/<int:request_id>', methods=['POST'])
@api_login_required
def respond_message_request(request_id):
    try:
        user = get_current_user()
        data = request.get_json()
        status = data.get('status', 'declined')
        
        if status not in ['accepted', 'declined']:
            return jsonify({'success': False, 'message': 'Invalid status'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM message_requests WHERE id = ? AND receiver_id = ?', (request_id, user['id']))
        request_data = cursor.fetchone()
        
        if not request_data:
            return jsonify({'success': False, 'message': 'Request not found or not authorized'}), 404
        
        updated_at = get_current_time()
        cursor.execute('UPDATE message_requests SET status = ?, updated_at = ? WHERE id = ?', 
                      (status, updated_at, request_id))
        
        conn.commit()
        
        if status == 'accepted':
            create_notification(request_data['sender_id'], 'message_request_accepted', '✅ Request Accepted',
                              f'{user["name"]} accepted your message request', url_for('chat', other_user_id=user["id"]))
        
        return jsonify({'success': True, 'message': f'Request {status}'})
        
    except Exception as e:
        print(f"Respond request error: {e}")
        return jsonify({'success': False, 'message': 'Failed to respond to request'}), 500


@app.route('/api/block-user/<int:user_id>', methods=['POST'])
@login_required
def api_block_user(user_id):
    try:
        if user_id == session['user_id']:
            return jsonify({'success': False, 'message': 'Cannot block yourself'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if already blocked
        cursor.execute('''
            SELECT id FROM blocked_users 
            WHERE blocker_id = ? AND blocked_id = ?
        ''', (session['user_id'], user_id))
        
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'User already blocked'}), 400
        
        # Block user
        cursor.execute('''
            INSERT INTO blocked_users (blocker_id, blocked_id)
            VALUES (?, ?)
        ''', (session['user_id'], user_id))
        
        conn.commit()
        conn.close()
        
        log_activity(session['user_id'], f'Blocked user {user_id}', True)
        
        return jsonify({'success': True, 'message': 'User blocked successfully'})
        
    except Exception as e:
        print(f"Block user error: {e}")
        return jsonify({'success': False, 'message': 'Failed to block user'}), 500

@app.route('/api/unblock-user/<int:user_id>', methods=['POST'])
@login_required
def api_unblock_user(user_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM blocked_users 
            WHERE blocker_id = ? AND blocked_id = ?
        ''', (session['user_id'], user_id))
        
        conn.commit()
        conn.close()
        
        log_activity(session['user_id'], f'Unblocked user {user_id}', True)
        
        return jsonify({'success': True, 'message': 'User unblocked successfully'})
        
    except Exception as e:
        print(f"Unblock user error: {e}")
        return jsonify({'success': False, 'message': 'Failed to unblock user'}), 500


@app.route('/api/report-user/<int:user_id>', methods=['POST'])
@login_required
def api_report_user(user_id):
    try:
        data = request.json
        reason = data.get('reason', '').strip()
        
        if not reason:
            return jsonify({'success': False, 'message': 'Reason is required'}), 400
        
        if user_id == session['user_id']:
            return jsonify({'success': False, 'message': 'Cannot report yourself'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Insert report
        cursor.execute('''
            INSERT INTO user_reports (reporter_id, reported_id, reason)
            VALUES (?, ?, ?)
        ''', (session['user_id'], user_id, reason))
        
        conn.commit()
        conn.close()
        
        log_activity(session['user_id'], f'Reported user {user_id}', True)
        
        return jsonify({'success': True, 'message': 'Report submitted successfully'})
        
    except Exception as e:
        print(f"Report user error: {e}")
        return jsonify({'success': False, 'message': 'Failed to submit report'}), 500
    
# ** ROUTE RESTORED AND FIXED **
@app.route('/api/send-message', methods=['POST'])
@api_login_required
def send_message():
    try:
        user = get_current_user()
        data = request.form
        
        receiver_id = int(data.get('receiver_id'))
        message = data.get('message', '').strip()
        shared_post_id = data.get('shared_post_id')
        
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename:
                image_filename = save_upload_file(file, 'messages', compress=True)
                if not image_filename:
                    return jsonify({'success': False, 'message': 'Invalid image file or upload failed'}), 400

        if not message and not image_filename and not shared_post_id:
            return jsonify({'success': False, 'message': 'Message cannot be empty'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT status FROM message_requests
            WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
              AND status = 'accepted'
        ''', (user['id'], receiver_id, receiver_id, user['id']))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Not allowed to message this user'}), 403
        
        created_at = get_current_time()
        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, message, image, shared_post_id, read, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
        ''', (user['id'], receiver_id, message or None, image_filename, shared_post_id, created_at))
        
        message_id = cursor.lastrowid
        conn.commit()
        
        # Get full message data for socket emission
        cursor.execute('''
            SELECT 
                m.id, m.sender_id, m.receiver_id, m.message as content, m.image as media_url, 
                m.shared_post_id, m.read, m.edited, m.created_at,
                s.name as sender_name
            FROM messages m
            LEFT JOIN users s ON m.sender_id = s.id
            WHERE m.id = ?
        ''', (message_id,))
        message_data = dict(cursor.fetchone())
        
        # Get shared post data if exists
        if message_data['shared_post_id']:
            cursor.execute('''
                SELECT 
                    p.id, p.content, p.image, p.status, p.section,
                    u.name as user_name, u.avatar as user_avatar
                FROM posts p
                LEFT JOIN users u ON p.user_id = u.id
                WHERE p.id = ?
            ''', (message_data['shared_post_id'],))
            post_data = cursor.fetchone()
            message_data['post_data'] = dict(post_data) if post_data else None
        else:
            message_data['post_data'] = None
        
        # Create notification
        create_notification(receiver_id, 'new_message', '💌 New Message',
                          f'{user["name"]} sent you a message', url_for('chat', other_user_id=user["id"]))
        
        log_activity(user['id'], 'Message Sent', True, f'To user {receiver_id}')
        
        # Emit socket event using the *new* efficient room name
        room_name = get_chat_room_name(user['id'], receiver_id)
        socketio.emit('new_message', message_data, room=room_name)
        
        return jsonify({
            'success': True,
            'message': 'Message sent successfully',
            'data': message_data # Send data back to sender for confirmation
        })
        
    except Exception as e:
        print(f"Send message error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to send message'}), 500

@app.route('/api/messages/<int:other_user_id>/read', methods=['POST'])
@api_login_required
def mark_messages_read(other_user_id):
    try:
        user = get_current_user()
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE messages 
            SET read = 1 
            WHERE sender_id = ? AND receiver_id = ? AND read = 0
        ''', (other_user_id, user['id']))
        
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Mark messages read error: {e}")
        return jsonify({'success': False}), 500

@app.route('/api/message/<int:message_id>/read', methods=['POST'])
@api_login_required
def mark_message_read(message_id):
    try:
        user = get_current_user()
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE messages 
            SET read = 1 
            WHERE id = ? AND receiver_id = ?
        ''', (message_id, user['id']))
        
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Mark message read error: {e}")
        return jsonify({'success': False}), 500

@app.route('/api/delete-message/<int:message_id>', methods=['DELETE'])
@api_login_required
def delete_message(message_id):
    try:
        user = get_current_user()
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT sender_id, receiver_id, image FROM messages WHERE id = ?
        ''', (message_id,))
        
        message = cursor.fetchone()
        
        if not message:
            return jsonify({'success': False, 'message': 'Message not found'}), 404
        
        if message['sender_id'] != user['id']:
            return jsonify({'success': False, 'message': 'Not authorized'}), 403
        
        if message['image']:
            delete_file(message['image'])
        
        cursor.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        
        log_activity(user['id'], 'Message Deleted', True, f'Message ID: {message_id}')
        
        # Emit socket event
        room_name = get_chat_room_name(user['id'], message['receiver_id'])
        socketio.emit('message_deleted', {'message_id': message_id}, room=room_name)
        
        return jsonify({'success': True, 'message': 'Message deleted successfully'})
        
    except Exception as e:
        print(f"Delete message error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to delete message'}), 500

@app.route('/api/post/<int:post_id>', methods=['GET'])
@api_login_required
def get_post_info(post_id):
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                p.id, p.user_id, p.content, p.image, p.status, p.section, p.created_at,
                u.name as user_name, u.avatar as user_avatar
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.id = ?
        ''', (post_id,))
        
        post = cursor.fetchone()
        
        if not post:
            return jsonify({'success': False, 'message': 'Post not found'}), 404
        
        return jsonify({
            'success': True,
            'post': dict(post)
        })
        
    except Exception as e:
        print(f"Get post info error: {e}")
        return jsonify({'success': False, 'message': 'Failed to load post'}), 500

@app.route('/api/forgot-password', methods=['POST'])
def api_forgot_password():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, email FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user:
            token = secrets.token_urlsafe(32)
            expiry = get_utc_now() + timedelta(hours=1)
            expiry_str = expiry.strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                UPDATE users 
                SET reset_token = ?, reset_token_expiry = ? 
                WHERE id = ?
            ''', (token, expiry_str, user['id']))
            conn.commit()
            
            # Send the email
            send_password_reset_email(user['email'], token)
            
        # Always return success to prevent email enumeration attacks
        return jsonify({'success': True, 'message': 'If an account with that email exists, a reset link has been sent.'})
        
    except Exception as e:
        print(f"Forgot password error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    try:
        data = request.get_json()
        token = data.get('token')
        password = data.get('password')
        
        if not token or not password:
            return jsonify({'success': False, 'message': 'Token and password are required'}), 400

        if len(password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
            
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT id, reset_token_expiry FROM users WHERE reset_token = ?', (token,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 400
        
        expiry_time = datetime.strptime(user['reset_token_expiry'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC_TIMEZONE)
        
        if get_utc_now() > expiry_time:
            return jsonify({'success': False, 'message': 'Token has expired'}), 400
        
        hashed_password = generate_password_hash(password)
        
        cursor.execute('''
            UPDATE users 
            SET password = ?, reset_token = NULL, reset_token_expiry = NULL, updated_at = ?
            WHERE id = ?
        ''', (hashed_password, get_current_time(), user['id']))
        conn.commit()
        
        log_activity(user['id'], 'Password Reset', True)
        
        return jsonify({'success': True, 'message': 'Password reset successfully!'})
        
    except Exception as e:
        print(f"API reset password error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/admin/users', methods=['GET'])
@api_login_required
@api_admin_required
def admin_get_users():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                id, name, email, avatar, phone, location, website,
                is_admin, email_verified, is_online, is_active, created_at, last_seen
            FROM users
            ORDER BY created_at DESC
        ''')
        users = [dict(row) for row in cursor.fetchall()]
        
        # Stats
        stats = {}
        cursor.execute('SELECT COUNT(*) as count FROM users')
        stats['total_users'] = cursor.fetchone()['count']
        cursor.execute('SELECT COUNT(*) as count FROM users WHERE is_online = 1')
        stats['online_users'] = cursor.fetchone()['count']
        cursor.execute('SELECT COUNT(*) as count FROM posts')
        stats['total_posts'] = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM posts WHERE DATE(created_at) >= DATE('now', 'utc')")
        stats['today_posts'] = cursor.fetchone()['count']
        cursor.execute('SELECT COUNT(*) as count FROM messages')
        stats['total_messages'] = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM messages WHERE DATE(created_at) >= DATE('now', 'utc')")
        stats['today_messages'] = cursor.fetchone()['count']
        cursor.execute('SELECT COUNT(*) as count FROM activity_log')
        stats['total_activity'] = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(DISTINCT user_id) as count FROM activity_log WHERE DATE(created_at) >= DATE('now', 'utc')")
        stats['active_today'] = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM message_requests WHERE status = 'pending'")
        stats['message_requests'] = cursor.fetchone()['count']
        cursor.execute("SELECT COUNT(*) as count FROM messages WHERE read = 0")
        stats['unread_messages'] = cursor.fetchone()['count']

        return jsonify({'success': True, 'users': users, 'stats': stats})
        
    except Exception as e:
        print(f"Admin get users error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': 'Failed to load users'}), 500

@app.route('/api/admin/posts', methods=['GET'])
@api_login_required
@api_admin_required
def admin_get_posts():
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                p.id, p.user_id, p.content, p.image, p.status, p.section, p.created_at,
                u.name as user_name,
                (SELECT COUNT(*) FROM post_likes WHERE post_id = p.id) as likes_count,
                (SELECT COUNT(*) FROM post_comments WHERE post_id = p.id) as comments_count
            FROM posts p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
            LIMIT 100
        ''')
        
        posts = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({'success': True, 'posts': posts})
        
    except Exception as e:
        print(f"Admin get posts error: {e}")
        return jsonify({'success': False, 'message': 'Failed to load posts'}), 500

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@api_login_required
@api_admin_required
def admin_delete_user(user_id):
    try:
        admin_user = get_current_user()
        
        if user_id == admin_user['id']:
            return jsonify({'success': False, 'message': 'You cannot delete your own account'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('SELECT is_admin, name, avatar FROM users WHERE id = ?', (user_id,))
        target_user = cursor.fetchone()
        
        if not target_user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if target_user['is_admin']:
            return jsonify({'success': False, 'message': 'Cannot delete another admin account'}), 403
        
        cursor.execute('SELECT image FROM posts WHERE user_id = ?', (user_id,))
        post_images = cursor.fetchall()
        
        if target_user['avatar']:
            delete_file(target_user['avatar'])
        
        for post in post_images:
            if post['image']:
                delete_file(post['image'])
        
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        
        log_activity(admin_user['id'], f'Admin deleted user: {target_user["name"]}', True, f'User ID: {user_id}')
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
        
    except Exception as e:
        print(f"Admin delete user error: {e}")
        return jsonify({'success': False, 'message': 'Failed to delete user'}), 500

@app.route('/api/admin/posts/<int:post_id>', methods=['DELETE'])
@api_login_required
@api_admin_required
def admin_delete_post(post_id):
    # This just calls the main delete_post function, which now has admin checks
    return delete_post(post_id)

@app.route('/api/notifications/<int:notif_id>/read', methods=['POST'])
@api_login_required
def mark_notification_read(notif_id):
    try:
        user = get_current_user()
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?', 
                      (notif_id, user['id']))
        conn.commit()
        
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500

@app.route('/api/notifications/mark-all-read', methods=['POST'])
@api_login_required
def mark_all_notifications_read():
    try:
        user = get_current_user()
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0', (user['id'],))
        conn.commit()
        
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500

@app.route('/api/notifications/<int:notif_id>', methods=['DELETE'])
@api_login_required
def delete_notification(notif_id):
    try:
        user = get_current_user()
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM notifications WHERE id = ? AND user_id = ?', 
                      (notif_id, user['id']))
        conn.commit()
        
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500

@app.route('/api/notifications/clear-all', methods=['DELETE'])
@api_login_required
def clear_all_notifications():
    try:
        user = get_current_user()
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM notifications WHERE user_id = ?', (user['id'],))
        conn.commit()
        
        return jsonify({'success': True})
    except:
        return jsonify({'success': False}), 500

# ==================== SOCKET.IO HANDLERS ====================

def get_chat_room_name(user1_id, user2_id):
    """Generate a consistent room name for two users"""
    if int(user1_id) > int(user2_id):
        return f'chat_{user2_id}_{user1_id}'
    return f'chat_{user1_id}_{user2_id}'

@socketio.on('connect')
def handle_connect():
    user_id = session.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        # ** FIX: Add app context **
        with app.app_context():
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_online = 1 WHERE id = ?', (user_id,))
                conn.commit()
            except Exception as e:
                print(f"Socket connect DB error: {e}")
        print(f"User {user_id} connected")

@socketio.on('disconnect')
def handle_disconnect():
    user_id = session.get('user_id')
    if user_id:
        leave_room(f'user_{user_id}')
        # ** FIX: Add app context **
        with app.app_context():
            try:
                conn = get_db()
                cursor = conn.cursor()
                last_seen = get_current_time()
                cursor.execute('UPDATE users SET is_online = 0, last_seen = ? WHERE id = ?', 
                             (last_seen, user_id))
                conn.commit()
            except Exception as e:
                print(f"Socket disconnect DB error: {e}")
        print(f"User {user_id} disconnected")

@socketio.on('join')
def handle_join(data):
    """Handle user joining their own room"""
    user_id = session.get('user_id')
    if user_id:
        join_room(f'user_{user_id}')
        print(f"User {user_id} explicitly joined user room")

@socketio.on('join_chat')
def handle_join_chat(data):
    """Handle user joining a specific chat room"""
    user_id = session.get('user_id')
    other_user_id = data.get('other_user_id')
    
    if user_id and other_user_id:
        room_name = get_chat_room_name(user_id, other_user_id)
        join_room(room_name)
        print(f"User {user_id} joined chat room: {room_name}")

@socketio.on('leave_chat')
def handle_leave_chat(data):
    """Handle user leaving a specific chat room"""
    user_id = session.get('user_id')
    other_user_id = data.get('other_user_id')
    
    if user_id and other_user_id:
        room_name = get_chat_room_name(user_id, other_user_id)
        leave_room(room_name)
        print(f"User {user_id} left chat room: {room_name}")

@socketio.on('typing')
def handle_typing(data):
    user_id = session.get('user_id')
    other_user_id = data.get('other_user_id')
    
    if user_id and other_user_id:
        room_name = get_chat_room_name(user_id, other_user_id)
        socketio.emit('user_typing', {
            'user_id': user_id
        }, room=room_name, skip_sid=request.sid)

@socketio.on('stopped_typing')
def handle_stopped_typing(data):
    user_id = session.get('user_id')
    other_user_id = data.get('other_user_id')
    
    if user_id and other_user_id:
        room_name = get_chat_room_name(user_id, other_user_id)
        socketio.emit('user_stopped_typing', {
            'user_id': user_id
        }, room=room_name, skip_sid=request.sid)

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    print(f"Internal error: {error}")
    import traceback
    traceback.print_exc()
    return render_template('500.html'), 500

@app.errorhandler(Exception)
def handle_exception(error):
    print(f"Unhandled exception: {error}")
    import traceback
    traceback.print_exc()
    
    # Handle werkzeug exceptions (like 405 Method Not Allowed)
    if hasattr(error, 'code'):
        if error.code == 404:
            return render_template('404.html'), 404
        if error.code == 500:
            return render_template('500.html'), 500
    
    return render_template('500.html'), 500

# ==================== MAIN ====================

if __name__ == '__main__':
    init_db()
    
    # Create default admin user (idempotent)
    try:
        with app.app_context():
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', ('admin@mfqod.com',))
            if not cursor.fetchone():
                admin_password = generate_password_hash('admin123')
                created_at = get_current_time()
                cursor.execute('''
                    INSERT INTO users (name, email, password, is_admin, email_verified, created_at, updated_at)
                    VALUES (?, ?, ?, 1, 1, ?, ?)
                ''', ('Admin', 'admin@mfqod.com', admin_password, created_at, created_at))
                conn.commit()
                print("=" * 60)
                print("✅ Default admin user created!")
                print("📧 Email: admin@mfqod.com")
                print("🔑 Password: admin123")
                print("⚠️  Please change password after first login!")
                print("=" * 60)
    except Exception as e:
        print(f"Admin user creation error: {e}")
    
    print("=" * 60)
    print("🚀 MFQOD Server Starting...")
    print("=" * 60)
    
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)