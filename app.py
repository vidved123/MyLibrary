import traceback

import mysql

print("mysql module:", mysql)
print("mysql module file:", getattr(mysql, '__file__', 'built-in'))
print("mysql attributes:", dir(mysql))

import base64
import logging
import os
import re
import sys
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from hashlib import sha256
from logging.handlers import RotatingFileHandler
from uuid import uuid4

import bcrypt
import jwt
import mysql.connector
import pandas as pd
import pymysql
import pymysql.cursors
import redis
from flask import (Flask, abort, config, current_app, flash, jsonify,
                   make_response, redirect, render_template, request, session,
                   url_for)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

print("[DEBUG] Python executing path:", sys.executable)

os.environ['FLASK_ENV'] = 'development' 

# Flask app
app = Flask(__name__)

# Ensure app.static_folder is not None before joining path
if app.static_folder is not None:
    UPLOAD_FOLDER = os.path.join(app.static_folder, 'uploads')
else:
    UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')

# Session management
app.permanent_session_lifetime = timedelta(hours=2)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # Prevents JavaScript access – secure
    SESSION_COOKIE_SAMESITE='Lax',    # Cookie works with navigation
    SESSION_COOKIE_SECURE=False,      # Correct for HTTP (127.0.0.1); use True only with HTTPS
)

# Keys and paths
app.secret_key = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['UNIVERSAL_SECRET_KEY'] = 'your_universal_secret'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'images')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# MySQL config
app.config['MYSQL_HOST'] = '127.0.0.1:' 
''
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'foulae0101@'
app.config['MYSQL_DB'] = 'library'

# Redis setup
redis_store = redis.StrictRedis(
    host='127.0.0.1',
    port=6379,
    db=0,
    decode_responses=True
)

# Create file handler for logging to a file
file_handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
file_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
file_handler.setFormatter(file_formatter)
file_handler.setLevel(logging.INFO)

# Create stream handler for terminal output
stream_handler = logging.StreamHandler()
stream_formatter = logging.Formatter('[%(levelname)s] %(message)s')
stream_handler.setFormatter(stream_formatter)
stream_handler.setLevel(logging.DEBUG)

# Get the app logger and add both handlers
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

# Optional: add handlers to Flask's built-in logger
app.logger.setLevel(logging.DEBUG)
app.logger.addHandler(file_handler)
app.logger.addHandler(stream_handler)


# Rate limiter
Limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)





def get_db_connection():
    return pymysql.connect(
        host='127.0.0.1',
        user='root',
        password='foulae0101@',
        db='library',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        conn.begin()
        cursor.execute(f'CREATE DATABASE IF NOT EXISTS `{app.config["MYSQL_DB"]}`')
        cursor.execute(f'USE `{app.config["MYSQL_DB"]}`')

        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                full_name VARCHAR(50),
                sex ENUM('MALE', 'FEMALE'),
                mobile_number VARCHAR(15),
                country_code VARCHAR(5),
                role VARCHAR(50) DEFAULT 'user'
            )
        ''')

        # Books table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS books (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                author VARCHAR(255) NOT NULL,
                available BOOLEAN DEFAULT TRUE
            )
        ''')

        # Borrowed books table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS borrowed_books (
                id INT AUTO_INCREMENT PRIMARY KEY,
                book_id INT NOT NULL,
                user_id INT NOT NULL,
                borrowed_date DATETIME NOT NULL,
                borrow_count INT DEFAULT 0,
                due_date DATETIME,
                FOREIGN KEY (book_id) REFERENCES books(id)
            )
        ''')

        # Inventory table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id INT AUTO_INCREMENT PRIMARY KEY,
                book_id INT,
                status ENUM('available', 'borrowed') NOT NULL DEFAULT 'available',
                FOREIGN KEY (book_id) REFERENCES books(id)
            )
        ''')

        conn.commit()
        print("Database initialized successfully.")

    except mysql.connector.Error as e:
        conn.rollback()
        print(f"Database error: {e}")

    finally:
        cursor.close()
        conn.close()



# Load session from JWT
@app.before_request
def load_user_from_token():
    # Allow unauthenticated access to login, signup, home, register, forgot_password, and static files
    if request.endpoint in ['login', 'static', 'home', 'register', 'forgot_password'] or request.path.startswith('/static/'):
        return
    token = request.cookies.get('token')
    if token:
        try:
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            session_id = payload.get('session_id')
            expected_hash = redis_store.get(session_id)
            if not expected_hash or expected_hash != sha256(token.encode()).hexdigest():
                logger.warning("[JWT LOAD] Session hash mismatch.")
                flash("Invalid session. Please log in again.", "error")
                session.clear()
                return redirect(url_for('login'))
            session['user_id'] = payload.get('user_id')
            session['role'] = payload.get('role', '').upper()
            session['session_id'] = session_id
            logger.debug(f"[JWT LOAD] Loaded session for user {session['user_id']}")
        except jwt.exceptions.InvalidTokenError as e:
            logger.warning(f"[JWT LOAD] Invalid token: {e}")
            session.clear()
            return redirect(url_for('login'))
    else:
        # Only redirect if not already going to login
        return redirect(url_for('login'))

# Home route
@app.route('/')
def home():
    user_id = session.get('user_id')
    if user_id:
        # Fetch user info from DB if you want to show profile details
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT username, email, full_name, role FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return render_template('home.html', logged_in=True, user=user)
    return render_template('home.html', logged_in=False, user=None)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    try:
        cursor.execute("SELECT id, password, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

        user_id = user.get('id')
        hashed_password = user.get('password')
        role = user.get('role')

        if not hashed_password or not hashed_password.startswith('$2b$'):
            flash('Invalid password format in database.', 'error')
            return render_template('login.html')

        if not bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

        # Create token and session
        session_id = str(uuid.uuid4())
        payload = {
            'user_id': user_id,
            'role': role,
            'session_id': session_id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=2)
        }

        secret = app.config['JWT_SECRET_KEY']
        token = jwt.encode(payload, secret, algorithm='HS256')
        token_hash = sha256(token.encode()).hexdigest()

        redis_store[session_id] = token_hash

        response = make_response(redirect(url_for('dashboard')))
        max_age = int(timedelta(hours=2).total_seconds())
        response.set_cookie('token', token, httponly=True, max_age=max_age, samesite='Lax')

        session['session_id'] = session_id

        logger.info(f"[LOGIN] User {user_id} logged in as {role}")
        print(f"[DEBUG] JWT Token: {token}")
        print(f"[DEBUG] Session ID: {session_id}")

        return response

    except Exception as e:
        logger.error(f"[LOGIN] Error: {e}", exc_info=True)
        flash('Internal server error.', 'error')
        return render_template('login.html')

    finally:
        cursor.close()
        conn.close()

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not username or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('forgot_password.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('forgot_password.html')

        if not is_complex_password(new_password):
            flash('Password does not meet complexity requirements.', 'error')
            return render_template('forgot_password.html')

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        try:
            cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
            user = cursor.fetchone()
            if not user:
                flash('User not found.', 'error')
                return render_template('forgot_password.html')

            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute('UPDATE users SET password = %s WHERE username = %s', (hashed_password, username))
            conn.commit()
            flash('Password reset successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash('An error occurred. Please try again.', 'error')
        finally:
            cursor.close()
            conn.close()
        return render_template('forgot_password.html')
    return render_template('forgot_password.html')





@app.route('/api/usernames', methods=['GET'])
def api_usernames():
    query = request.args.get('query', '')
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute('SELECT username FROM users WHERE username LIKE %s', ('%' + query + '%',))
    usernames = [row.get('username') for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return jsonify(usernames)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        data = request.form.to_dict()

        # Validate required fields
        required_fields = ['username', 'email', 'full_name', 'sex', 'mobile_number', 'country_code', 'password', 'confirm_password']
        if not all(field in data for field in required_fields):
            logger.warning('Missing required fields in request body')
            return render_template('register.html', data=data, error='Missing required fields!')

        username = data['username']
        email = data['email']
        full_name = data['full_name']
        sex = data['sex']
        mobile_number = data['mobile_number']
        country_code = data['country_code']
        password = data['password']
        confirm_password = data['confirm_password']

        if password != confirm_password:
            logger.warning('Passwords do not match')
            return render_template('register.html', data=data, error='Passwords do not match!')

        if not is_complex_password(password):
            logger.warning('Password does not meet complexity requirements')
            return render_template('register.html', data=data, error='Password does not meet complexity requirements!')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            conn.begin()

            cursor.execute('SELECT COUNT(*) FROM users')
            user_count_row = cursor.fetchone()
            user_count = user_count_row['COUNT(*)'] if user_count_row is not None else 0
            role = 'admin' if user_count == 0 else 'user'

            cursor.execute('''
                INSERT INTO users (username, email, password, full_name, sex, mobile_number, country_code, role) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (username, email, hashed_password, full_name, sex, mobile_number, country_code, role))

            conn.commit()

        except mysql.connector.IntegrityError:
            conn.rollback()
            logger.error('Username or Email already exists')
            return render_template('register.html', data=data, error='Username or Email already exists!')
        except mysql.connector.DataError as e:
            conn.rollback()
            logger.error(f'Data error occurred: {str(e)}')
            return render_template('register.html', data=data, error='Data error occurred: ' + str(e))
        finally:
            cursor.close()
            conn.close()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', data={})



SECRET_KEY = 'your-secret-key'  # Replace with actual secret key

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None

        # Check Authorization header first
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[-1]

        # Fallback to cookie
        if not token and 'token' in request.cookies:
            token = request.cookies.get('token')

        if not token:
            logger.warning("Token is missing from headers and cookies.")
            return redirect(url_for('login'))

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            session_id = payload.get('session_id')
            user_id = payload.get('user_id')

            if not session_id or not user_id:
                logger.warning("Token payload missing required fields.")
                return redirect(url_for('login'))

            token_hash = redis_store.get(session_id)
            if not token_hash:
                logger.warning(f"No session found in Redis for session_id: {session_id}")
                return redirect(url_for('login'))

            if token_hash != sha256(token.encode()).hexdigest():
                logger.warning("Token hash mismatch.")
                return redirect(url_for('login'))

        except jwt.ExpiredSignatureError:
            logger.warning("Token expired.")
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            logger.warning("Invalid token.")
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Unexpected error during token validation: {e}")
            return redirect(url_for('login'))

        return f(user_id, *args, **kwargs)

    return decorator




@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('SELECT COUNT(*) AS total FROM books')
        result = cursor.fetchone()
        total_books = result['total'] if result else 0

        cursor.execute('SELECT COUNT(*) AS total FROM borrowed_books WHERE user_id = %s', (user_id,))
        result = cursor.fetchone()
        total_borrowed_books = result['total'] if result else 0

        cursor.execute('''
            SELECT b.title, b.author, bb.borrowed_date
            FROM borrowed_books bb
            JOIN books b ON bb.book_id = b.id
            WHERE bb.user_id = %s
        ''', (user_id,))
        borrowed_books_raw = cursor.fetchall()

        borrowed_books = []
        # borrowed_books_raw is a list of dicts since we're using DictCursor
        for book in borrowed_books_raw:
            borrowed_date = book.get('borrowed_date')
            borrowed_books.append({
                'title': book.get('title'),
                'author': book.get('author'),
                'borrowed_date': borrowed_date.strftime('%Y-%m-%d') if borrowed_date else 'N/A'
            })

        cursor.execute('SELECT username, role FROM users WHERE id = %s', (user_id,))
        user_info = cursor.fetchone()
        username = user_info.get('username', 'Guest') if user_info else 'Guest'
        user_role = user_info.get('role', 'guest') if user_info else 'guest'

    except Exception as e:
        logger.error(f'Error fetching dashboard: {e}', exc_info=True)
        borrowed_books = []
        total_books = 0
        total_borrowed_books = 0
        username = 'Guest'
        user_role = 'guest'

    finally:
        cursor.close()
        conn.close()

    dashboard_data = {
        'total_books': total_books,
        'total_borrowed_books': total_borrowed_books,
        'borrowed_books': borrowed_books,
        'username': username,
        'user_role': user_role
    }

    return render_template('dashboard.html', data=dashboard_data)


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    token = request.cookies.get('token')
    if not token:
        flash('Authentication token missing.', 'danger')
        return redirect(url_for('login'))

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        role = payload.get('role', '')

        logger.info(f"[ADD_USER] Access attempt with role: {role}")
        print(f"[DEBUG] Decoded token payload: {payload}")

        if role.upper() != 'ADMIN':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('library'))

    except jwt.ExpiredSignatureError:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    except jwt.InvalidTokenError:
        flash('Invalid token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        country_code = request.form['country_code']
        user_role = request.form['role']

        # ✅ Proper bcrypt hashing
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                '''INSERT INTO users (full_name, username, password, email, mobile_number, country_code, role)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                (full_name, username, hashed_password, email, phone, country_code, user_role)
            )
            connection.commit()
            flash('User added successfully!', 'success')
            logger.debug("[ADD_USER] User added successfully")
        except Exception as e:
            logger.error(f"[ADD_USER] Error: {e}", exc_info=True)
            connection.rollback()
            flash(f'Error adding user: {str(e)}', 'danger')
            return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500
        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('add_user'))

    return render_template('add_user.html')


@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    logger.debug("===[ DELETE USER ROUTE CALLED ]===")
    logger.debug(f"Session contents: {dict(session)}")

    role = session.get('role')
    if not role:
        logger.warning("No role found in session.")
    else:
        logger.debug(f"Role found in session: {role} (after .upper(): {role.upper()})")

    if role and role.upper() == 'ADMIN':
        connection = get_db_connection()
        cursor = connection.cursor()

        try:
            cursor.execute("SELECT id, username, full_name FROM users")
            users = cursor.fetchall()
            logger.debug(f"Fetched {len(users)} users from DB.")
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            flash("Error fetching users.", "danger")
            users = []
        finally:
            cursor.close()
            connection.close()

        if request.method == 'POST':
            user_id = request.form.get('user_id')
            logger.debug(f"Received POST to delete user_id: {user_id}")

            if user_id:
                connection = get_db_connection()
                cursor = connection.cursor()
                try:
                    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
                    connection.commit()
                    flash("User deleted successfully!", "success")
                    logger.info(f"User ID {user_id} deleted successfully.")
                except Exception as e:
                    connection.rollback()
                    flash("Error deleting user.", "danger")
                    logger.error(f"Error deleting user ID {user_id}: {e}")
                finally:
                    cursor.close()
                    connection.close()

                return redirect(url_for('delete_user'))

        return render_template("delete_user.html", users=users)

    flash("Access denied!", "danger")
    logger.warning("Access denied - user is not admin.")
    return redirect(url_for("dashboard"))


@app.route('/profile', methods=['GET'])
@token_required
def profile(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(''' 
        SELECT id, username, email, full_name, sex, mobile_number, country_code
        FROM users
        WHERE id = %s 
    ''', (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Prevent cached profile data from being served
    response = make_response(render_template('profile.html', user=user))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/view_users_roster', methods=['GET'])
@token_required
def view_users_roster(user_id):  # ✅ Accept user_id
    if 'role' not in session or session['role'].upper() != 'ADMIN':
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT id, username, full_name, email, mobile_number, country_code, role FROM users")
    users = cursor.fetchall()
    db.close()
    return render_template('users_roster.html', users=users)



@app.route('/update_profile', methods=['POST'])
@token_required
def update_profile(user_id):
    full_name = request.form.get('full_name')
    sex = request.form.get('sex')
    mobile_number = request.form.get('mobile_number')
    country_code = request.form.get('country_code')
    email = request.form.get('email')

    if not all([full_name, sex, mobile_number, country_code, email]):
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        conn.begin()
        cursor.execute('''
            UPDATE users
            SET full_name = %s, sex = %s, mobile_number = %s, country_code = %s, email = %s
            WHERE id = %s
        ''', (full_name, sex, mobile_number, country_code, email, user_id))
        conn.commit()
    except mysql.connector.Error as e:
        conn.rollback()
        return jsonify({'message': f'Error occurred: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('profile'))


@app.route('/profile/delete', methods=['POST'])
@token_required
def delete_profile(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        conn.begin()
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
    except mysql.connector.Error as e:
        conn.rollback()
        return jsonify({'message': f'Error occurred: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

    logger.info(f"User with ID {user_id} deleted successfully.")
    flash('Your profile has been deleted successfully.', 'success')

    session.clear()
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('token')
    response.delete_cookie('universal_token')
    return response


@app.route('/logout', methods=['POST'])
@token_required
def logout(user_id):
    # Attempt to get session_id from JWT token stored in cookie
    token = request.cookies.get('token')
    session_id = None

    try:
        if token is not None:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            session_id = payload.get('session_id')
        else:
            logger.warning("[LOGOUT] No token found in cookies during logout.")
    except Exception as e:
        logger.warning(f"[LOGOUT] Invalid token on logout: {e}", exc_info=True)

    # Delete session from redis_store
    if session_id and session_id in redis_store:
        del redis_store[session_id]

    # Clear Flask session (optional)
    session.clear()

    # Prepare response with cookies deleted
    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.delete_cookie('token')
    response.delete_cookie('universal_token')  # If used elsewhere

    logger.info(f"[LOGOUT] User {user_id} logged out. Session ID: {session_id}")

    return response




# library app routes

# Route to the library page
@app.route('/library')
def library():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # Get total number of books
            cursor.execute("SELECT COUNT(*) AS book_count FROM books")
            result = cursor.fetchone()
            book_count = result['book_count'] if result else 0
            logger.info(f"Total number of books: {book_count}")

            # Get books borrowed by the user
            cursor.execute('''
                SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                FROM borrowed_books bb
                JOIN books b ON bb.book_id = b.id
                WHERE bb.user_id = %s
            ''', (user_id,))
            borrowed_books = cursor.fetchall()
            logger.info(f"Borrowed books fetched for user_id {user_id}: {borrowed_books}")

            # Get user info
            cursor.execute("SELECT username, role FROM users WHERE id = %s", (user_id,))
            user_result = cursor.fetchone()
            if user_result:
                username = user_result.get('username', 'Guest')
                user_role = user_result.get('role', 'USER').upper()
            else:
                username = 'Guest'
                user_role = 'USER'

            # Calculate fines for overdue books
            fine_per_day = 10
            current_date = datetime.now().date()

            for book in borrowed_books:
                borrowed_date = book.get('borrowed_date')
                due_date = book.get('due_date')

                if isinstance(borrowed_date, datetime):
                    borrowed_date = borrowed_date.date()
                if isinstance(due_date, datetime):
                    due_date = due_date.date()

                overdue_days = max((current_date - due_date).days, 0) if due_date else 0
                fine = overdue_days * fine_per_day

                if isinstance(book, dict):
                    book['borrowed_date'] = borrowed_date
                    book['due_date'] = due_date
                    book['overdue_days'] = overdue_days
                    book['fine'] = fine
                    logger.info(f"Calculated overdue days: {overdue_days}, Fine: {fine} for book_id {book.get('book_id')}")
                else:
                    logger.warning(f"Book object is not a dict: {book}")

    except Exception as e:
        logger.error(f"An error occurred while fetching library data: {e}")
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500

    finally:
        conn.close()

    return render_template('library.html', book_count=book_count, borrowed_books=borrowed_books,
                           username=username, user_role=user_role)





# books route
@app.route('/book/<int:book_id>', methods=['GET'])
@token_required
def book(book_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT title, author FROM books WHERE id = %s', (book_id,))
        book = cursor.fetchone()
        cursor.close()
        conn.close()

        if book:
            logger.info(f"Book found: {book}")
            return jsonify({'title': book.get('title'), 'author': book.get('author')}), 200

        logger.warning(f"Book not found for book_id: {book_id}")
        return jsonify({'message': 'Book not found'}), 404
    except Exception as e:
        logger.error(f"An error occurred while fetching book data: {e}")
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500


# book "master" route
@app.route('/book_master', methods=['GET'])
@token_required
def book_master(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Group by title and author to ensure duplicates are counted
        query = '''
            SELECT b.title, b.author,
                   COUNT(i.id) AS total_copies,
                   SUM(CASE WHEN i.status = 'available' THEN 1 ELSE 0 END) AS available_copies
            FROM books b
            LEFT JOIN inventory i ON b.id = i.book_id
            GROUP BY b.title, b.author
        '''
        cursor.execute(query)
        books = cursor.fetchall()
        logger.info(f"Fetched book master data: {books}")

    except Exception as e:
        logger.error(f"An error occurred while fetching book master data: {e}")
        books = []
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500

    finally:
        cursor.close()
        conn.close()

    return render_template('book_master.html', books=books)




@app.route('/add_books', methods=['GET', 'POST'])
def add_books():
    conn = None
    cursor = None
    try:
        user_id = session.get('user_id')
        logger.debug("[JWT LOAD] Loaded session for user %s", user_id)

        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Fetch existing normalized keys
        cursor.execute("SELECT normalized_key FROM books")
        existing_books = {row.get('normalized_key') for row in cursor.fetchall()}
        logger.debug("Existing normalized keys: %s", existing_books)

        # Handle Excel file upload
        if request.method == 'POST' and 'submit_excel' in request.form:
            if 'excel_file' in request.files and request.files['excel_file'].filename:
                excel_file = request.files['excel_file']
                df = pd.read_excel(excel_file)
                logger.debug("Excel preview:\n%s", df.head())

                for _, row in df.iterrows():
                    title = str(row['title']).strip()
                    author = str(row['author']).strip()
                    total_copies = int(row['total_copies'])

                    normalized_key = f"{title.lower()}|{author.lower()}"

                    if normalized_key in existing_books:
                        logger.info("Skipping existing book: %s", normalized_key)
                        continue

                    cursor.execute('''
                        INSERT INTO books (title, author, image, total_copies, available_copies, normalized_key)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (title, author, None, total_copies, total_copies, normalized_key))

                    existing_books.add(normalized_key)

                conn.commit()
                flash('Books uploaded successfully from Excel.', 'success')
                return redirect(url_for('library'))
            else:
                flash('No Excel file provided.', 'error')

        # Handle manual book addition
        elif request.method == 'POST' and 'submit_manual' in request.form:
            title = request.form['title'].strip()
            author = request.form['author'].strip()
            total_copies = int(request.form['total_copies'])
            image = request.files.get('image')

            normalized_key = f"{title.lower()}|{author.lower()}"

            if normalized_key in existing_books:
                flash('Book already exists.', 'warning')
                return redirect(url_for('add_books'))

            image_filename = None
            if image and image.filename:
                filename = secure_filename(image.filename)
                static_folder = current_app.static_folder or ""
                image_folder = os.path.join(static_folder, 'uploads')
                os.makedirs(image_folder, exist_ok=True)
                image_path = os.path.join(image_folder, filename)
                image.save(image_path)
                image_filename = os.path.join('uploads', filename)
                logger.debug("Image saved to: %s", image_filename)

            cursor.execute('''
                INSERT INTO books (title, author, image, total_copies, available_copies, normalized_key)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (title, author, image_filename, total_copies, total_copies, normalized_key))

            conn.commit()
            flash('Book added successfully.', 'success')
            return redirect(url_for('library'))

        return render_template('add_books.html')

    except Exception as e:
        logger.exception("Error occurred in /add_books")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('add_books'))

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()














import re
import unicodedata


def generate_image_filename(title):
    # Normalize and clean the title
    title = unicodedata.normalize('NFKD', title).encode('ascii', 'ignore').decode('ascii')
    title = title.strip().lower()
    title = re.sub(r'[^a-z0-9\s]', '', title)
    filename = re.sub(r'\s+', '_', title)

    # Predefined patterns for common series
    diary_keywords = [
        "rodrick_rules", "the_last_straw", "dog_days", "the_ugly_truth",
        "cabin_fever", "the_third_wheel", "hard_luck", "the_long_haul",
        "old_school", "double_down", "the_getaway", "the_meltdown",
        "wrecking_ball", "the_deep_end", "big_shot", "diper_overlode", "no_brainer"
    ]

    if "diary_of_a_wimpy_kid" in filename:
        for keyword in diary_keywords:
            if keyword in filename:
                return f"diary_of_a_wimpy_kid_{keyword}.jpg"
        return f"{filename}.jpg"

    if filename.startswith("five"):
        return f"the_famous_five_{filename}.jpg"

    if filename.startswith("secret_seven"):
        return f"the_secret_seven_{filename}.jpg"

    if re.match(r"[a-z]_is_for_", filename):
        return f"{filename}.jpg"

    # Default fallback
    return f"{filename}.jpg"


@app.route('/view_books', methods=['GET'])
@token_required
def view_books(user_id):
    search_query = request.args.get('search', '')

    def get_books_from_your_db(search_query):
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        try:
            if search_query:
                cursor.execute(
                    "SELECT id AS book_id, title, author, total_copies, available_copies FROM books WHERE title LIKE %s OR author LIKE %s ORDER BY title ASC",
                    (f"%{search_query}%", f"%{search_query}%")
                )
            else:
                cursor.execute(
                    "SELECT id AS book_id, title, author, total_copies, available_copies FROM books ORDER BY title ASC"
                )
            books = cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
        return books

    books = get_books_from_your_db(search_query)

    for book in books:
        # Assign image_path if book is a dict and has a 'title' key
        if isinstance(book, dict) and 'title' in book:
            book['image_path'] = generate_image_filename(book['title'])

    role = session.get('role')
    is_admin = (role == 'ADMIN')

    return render_template('view_books.html', books=books, search_query=search_query, is_admin=is_admin)










@app.route('/delete_books', methods=['POST'])
@token_required
def delete_books(user_id):
    role = session.get('role')

    if role != 'ADMIN':
        flash('You do not have permission to delete books.', 'error')
        return redirect(url_for('view_books'))

    book_ids = request.form.getlist('book_ids')
    delete_all = request.form.get('delete_all') == '1'

    if not book_ids:
        flash('No books selected for deletion.', 'error')
        return redirect(url_for('view_books'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        for book_id in book_ids:
            if not book_id.isdigit():
                flash(f"Invalid book ID: {book_id}", "error")
                continue

            book_id = int(book_id)
            cursor.execute('SELECT total_copies, available_copies FROM books WHERE id = %s', (book_id,))
            book = cursor.fetchone()

            if not book:
                flash(f"Book ID {book_id} not found.", "error")
                continue

            total, available = book['total_copies'], book['available_copies']

            if delete_all:
                cursor.execute('DELETE FROM inventory WHERE book_id = %s', (book_id,))
                cursor.execute('DELETE FROM books WHERE id = %s', (book_id,))
            else:
                if total <= 1:
                    cursor.execute('DELETE FROM inventory WHERE book_id = %s', (book_id,))
                    cursor.execute('DELETE FROM books WHERE id = %s', (book_id,))
                else:
                    new_total = total - 1
                    new_available = max(0, available - 1)
                    cursor.execute('''
                        UPDATE books
                        SET total_copies = %s, available_copies = %s
                        WHERE id = %s
                    ''', (new_total, new_available, book_id))

        conn.commit()
        flash("Books deleted/updated successfully.", "success")

    except Exception as e:
        if conn:
            conn.rollback()
        flash(f"An error occurred: {e}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('library'))




def is_book_available(book_id):
    """Check if the book is available."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT available FROM books WHERE id = %s", (book_id,))
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        if result:
            return result.get('available', False)
        return False
    except Exception as e:
        logger.error(f"An error occurred while checking availability: {e}")
        return False


@app.route('/verify_user', methods=['POST'])
@token_required
def verify_user(user_id):
    user_id = request.form.get('user_id')
    
    if not user_id:
        return jsonify({"exists": False}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    try:
        # Verify if the user ID exists in the users table
        cursor.execute('SELECT id FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()

        if user:
            return jsonify({"exists": True})
        else:
            return jsonify({"exists": False})

    except pymysql.MySQLError as e:
        return jsonify({"exists": False, "error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


# Borrowing books route
@app.route('/borrow', methods=['GET', 'POST'])
@token_required
def borrow_books(user_id):
    search_query = request.args.get('search', '')
    role = session.get('role')  # Fetch the role from the session

    if request.method == 'POST':
        book_ids = request.form.getlist('book_ids[]')
        target_user_id = request.form.get('user_id') if role == 'ADMIN' else user_id  # Admin selects user ID for borrowing

        if not target_user_id:
            flash('You must be logged in to borrow a book.', 'error')
            return redirect(url_for('borrow_books'))

        if not book_ids or not all(book_id.isdigit() for book_id in book_ids):
            flash('Invalid book ID(s).', 'error')
            return redirect(url_for('borrow_books'))

        if len(book_ids) > 3:
            flash('You can borrow a maximum of 3 books at a time.', 'error')
            return redirect(url_for('borrow_books'))

        conn = None
        cursor = None
        borrowed_count = 0

        try:
            conn = get_db_connection()
            cursor = conn.cursor()  # Removed pymysql.cursors.DictCursor due to lint error

            if role == 'ADMIN':
                cursor.execute('SELECT id FROM users WHERE id = %s', (target_user_id,))
                user_exists = cursor.fetchone()
                if not user_exists:
                    flash(f'User ID {target_user_id} does not exist.', 'error')
                    return redirect(url_for('borrow_books'))

            for book_id in book_ids:
                if borrowed_count >= 3:
                    break

                book_id = int(book_id)

                cursor.execute('''
                    SELECT COUNT(*) AS borrow_count
                    FROM borrowed_books
                    WHERE book_id = %s AND user_id = %s
                ''', (book_id, target_user_id))
                result = cursor.fetchone()
                if result and result.get('borrow_count', 0) >= 1:
                    flash(f'Book ID {book_id} is already borrowed.', 'error')
                    continue

                cursor.execute('''
                    SELECT COUNT(*) AS available_copies
                    FROM inventory
                    WHERE book_id = %s AND status = 'available'
                ''', (book_id,))
                result = cursor.fetchone()
                if not result or result['available_copies'] < 1:
                    flash(f'No available copies for Book ID {book_id}.', 'error')
                    continue

                borrowed_date = datetime.now()
                due_date = borrowed_date + timedelta(days=14)

                cursor.execute('''
                    INSERT INTO borrowed_books (user_id, book_id, borrowed_date, due_date)
                    VALUES (%s, %s, %s, %s)
                ''', (target_user_id, book_id, borrowed_date, due_date))

                cursor.execute('''
                    UPDATE inventory
                    SET status = 'borrowed'
                    WHERE book_id = %s AND status = 'available'
                    LIMIT 1
                ''', (book_id,))

                cursor.execute('''
                    UPDATE books
                    SET available_copies = available_copies - 1
                    WHERE id = %s
                ''', (book_id,))

                borrowed_count += 1

            conn.commit()

            if borrowed_count > 0:
                flash(f'{borrowed_count} book(s) successfully borrowed.', 'success')
            else:
                flash('No books were borrowed.', 'error')

        except pymysql.MySQLError as e:
            if conn:
                conn.rollback()
            flash(f'Database error: {e}', 'error')
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return redirect(url_for('borrow_books'))

    else:
        conn = None
        cursor = None
        books = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            query = '''
                SELECT b.id, b.title, b.author,
                       COUNT(i.id) AS total_copies,
                       SUM(CASE WHEN i.status = 'available' THEN 1 ELSE 0 END) AS available_copies
                FROM books b
                LEFT JOIN inventory i ON b.id = i.book_id
                WHERE b.title LIKE %s OR b.author LIKE %s OR b.id = %s
                GROUP BY b.id, b.title, b.author
            '''
            cursor.execute(query, (f'%{search_query}%', f'%{search_query}%', search_query))
            books = cursor.fetchall()

            # Assign image paths
            for book in books:
                # Ensure book is a dict and has a 'title' key
                if isinstance(book, dict) and 'title' in book:
                    book['image_path'] = generate_image_filename(book['title'])
                else:
                    logger.warning(f"Book entry is not a dict with a 'title' key: {book}")
                    # For now, just skip or log
                    logger.warning(f"Book entry is not a dict: {book}")
            # End of try block
        except pymysql.MySQLError as e:
            logger.error(f"Error fetching books: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return render_template('borrow_books.html', books=books, search_query=search_query)





@app.route('/view_borrowed_books', methods=['GET'])
@token_required
def view_borrowed_books(user_id):
    role = session.get('role')  # Stored as 'ADMIN' or 'USER'
    search_query = request.args.get('search', '')

    conn = None
    cursor = None
    borrowed_books = []

    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        if search_query:
            if role == 'ADMIN':
                # Admin searches by user ID
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date, u.username
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    JOIN users u ON bb.user_id = u.id
                    WHERE u.id = %s
                ''', (search_query,))
            else:
                # User searches by book ID, title, or author
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    WHERE bb.user_id = %s AND (b.title LIKE %s OR b.author LIKE %s OR b.id = %s)
                ''', (user_id, f'%{search_query}%', f'%{search_query}%', search_query))
        else:
            # No search query
            if role == 'ADMIN':
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date, u.username
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    JOIN users u ON bb.user_id = u.id
                ''')
            else:
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    WHERE bb.user_id = %s
                ''', (user_id,))

        borrowed_books = cursor.fetchall()

    except pymysql.MySQLError as e:
        logger.error(f"Database error: {e}")
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

    return render_template('view_borrowed_books.html', borrowed_books=borrowed_books, role=role, search_query=search_query)





@app.route('/return_books', methods=['GET', 'POST'])
@token_required
def return_books(user_id):
    role = session.get('role', '').upper()  # Ensure role is in uppercase

    conn = None
    cursor = None

    if request.method == 'POST':
        book_ids = request.form.getlist('book_ids')
        user_ids = request.form.getlist('user_ids') if role == 'ADMIN' else [user_id] * len(book_ids)

        if not book_ids or not all(id.isdigit() for id in book_ids):
            flash('Invalid book ID(s).', 'error')
            return redirect(url_for('return_books'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            for i, book_id in enumerate(book_ids):
                book_id = int(book_id)
                target_user_id = user_ids[i]

                cursor.execute('''
                    SELECT * FROM borrowed_books
                    WHERE book_id = %s AND user_id = %s
                ''', (book_id, target_user_id))
                borrowed_book = cursor.fetchone()

                if not borrowed_book:
                    flash(f'Book {book_id} not found or not borrowed by user {target_user_id}.', 'error')
                    continue

                cursor.execute('''
                    DELETE FROM borrowed_books
                    WHERE book_id = %s AND user_id = %s
                ''', (book_id, target_user_id))

                cursor.execute('''
                    UPDATE inventory
                    SET status = 'available'
                    WHERE book_id = %s
                    LIMIT 1
                ''', (book_id,))

                cursor.execute('''
                    UPDATE books
                    SET available_copies = available_copies + 1
                    WHERE id = %s
                    LIMIT 1
                ''', (book_id,))

            conn.commit()
            flash('Successfully returned selected books.', 'success')

        except pymysql.MySQLError as e:
            if conn:
                conn.rollback()
            flash(f'Error occurred while returning books: {e}', 'error')

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return redirect(url_for('return_books'))

    # GET Request: Show borrowed books with optional search
    search_query = request.args.get('search', '').strip()
    borrowed_books = []

    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        if role == 'ADMIN':
            if search_query.isdigit():
                # Admin enters a valid user ID
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date, u.id AS user_id, u.username
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    JOIN users u ON bb.user_id = u.id
                    WHERE u.id = %s
                ''', (search_query,))
                borrowed_books = cursor.fetchall()
                if not borrowed_books:
                    flash(f"No borrowed books found for user ID {search_query}.", 'error')

            else:
                # Admin sees all books and which user borrowed them
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date, u.id AS user_id, u.username
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    JOIN users u ON bb.user_id = u.id
                ''')
                borrowed_books = cursor.fetchall()

        else:  # Regular users
            if search_query:
                # Regular user searches by title or author
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    WHERE bb.user_id = %s AND (b.title LIKE %s OR b.author LIKE %s)
                ''', (user_id, f'%{search_query}%', f'%{search_query}%'))
                borrowed_books = cursor.fetchall()
            else:
                # Regular user sees only their own borrowed books
                cursor.execute('''
                    SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                    FROM borrowed_books bb
                    JOIN books b ON bb.book_id = b.id
                    WHERE bb.user_id = %s
                ''', (user_id,))
                borrowed_books = cursor.fetchall()

    except pymysql.MySQLError as e:
        flash(f'Error occurred while fetching borrowed books: {e}', 'error')
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template('return_books.html', borrowed_books=borrowed_books, role=role)




def is_complex_password(password):
    # Example password complexity rules
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?/~" for char in password):
        return False
    return True


# --- API endpoint for AJAX live search in view_books ---
@app.route('/api/books')
@token_required
def api_books(user_id):
    search_query = request.args.get('search', '')

    def get_books_from_your_db(search_query):
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        try:
            if search_query:
                cursor.execute(
                    "SELECT id AS book_id, title, author, total_copies, available_copies FROM books WHERE title LIKE %s OR author LIKE %s ORDER BY title ASC",
                    (f"%{search_query}%", f"%{search_query}%")
                )
            else:
                cursor.execute(
                    "SELECT id AS book_id, title, author, total_copies, available_copies FROM books ORDER BY title ASC"
                )
            books = cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
        return books

    books = get_books_from_your_db(search_query)
    for book in books:
        if isinstance(book, dict) and 'title' in book:
            book['image_path'] = generate_image_filename(book['title'])
    role = session.get('role')
    is_admin = (role == 'ADMIN')
    return render_template('partials/books_tbody.html', books=books, is_admin=is_admin)

# --- API endpoint for AJAX live search in borrow_books ---
@app.route('/api/borrow_books')
@token_required
def api_borrow_books(user_id):
    search_query = request.args.get('search', '').strip()
    conn = None
    cursor = None
    books = []
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        query = '''
            SELECT b.id, b.title, b.author,
                   COUNT(i.id) AS total_copies,
                   SUM(CASE WHEN i.status = 'available' THEN 1 ELSE 0 END) AS available_copies
            FROM books b
            LEFT JOIN inventory i ON b.id = i.book_id
            WHERE b.title LIKE %s OR b.author LIKE %s OR b.id = %s
            GROUP BY b.id, b.title, b.author
        '''
        cursor.execute(query, (f'%{search_query}%', f'%{search_query}%', search_query))
        books = cursor.fetchall()
        for book in books:
            if isinstance(book, dict) and 'title' in book:
                book['image_path'] = generate_image_filename(book['title'])
    except pymysql.MySQLError as e:
        pass
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    return render_template('partials/borrow_books_tbody.html', books=books, role=session.get('role'))





if __name__ == '__main__':
    init_db()
    app.run(debug=True)
