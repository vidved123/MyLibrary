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
from multiprocessing import connection
from uuid import uuid4

import bcrypt
import jwt
import mysql.connector
import pandas as pd
import pymysql
import redis
from flask import (Flask, abort, config, flash, jsonify, make_response,
                   redirect, render_template, request, session, url_for)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

print("[DEBUG] Python executing path:", sys.executable)

os.environ['FLASK_ENV'] = 'development' 



# Flask app
app = Flask(__name__)

# Session management
app.permanent_session_lifetime = timedelta(hours=2)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # Prevents JavaScript access – secure
    SESSION_COOKIE_SAMESITE='Lax',    # Cookie works with navigation
    SESSION_COOKIE_SECURE=False,      # Correct for HTTP (localhost); use True only with HTTPS
)

# Keys and paths
app.secret_key = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['UNIVERSAL_SECRET_KEY'] = 'your_universal_secret'
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'images')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# MySQL config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'foulae0101@'
app.config['MYSQL_DB'] = 'library'

# Redis setup
redis_store = redis.StrictRedis(
    host='localhost',
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
        host='localhost',
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


@app.before_request
def load_user_from_token():
    token = request.cookies.get('token')
    if token:
        try:
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            session['user_id'] = payload.get('user_id')
            session['role'] = payload.get('role', '').upper()
            session['session_id'] = payload.get('session_id')

            logger.debug(f"[JWT LOAD] Loaded session from token: {dict(session)}")
        except jwt.ExpiredSignatureError:
            logger.warning("[JWT LOAD] Token expired.")
            session.clear()
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for('login'))
        except jwt.InvalidTokenError as e:
            logger.warning(f"[JWT LOAD] Invalid token: {e}")
            session.clear()
            flash("Invalid session. Please log in again.", "error")
            return redirect(url_for('login'))
    else:
        logger.debug("[JWT LOAD] No token found in request.")

        # home route
@app.route('/')
def home():
    token = request.cookies.get('token')
    if token:
        return render_template('home.html', logged_in=True)
    else:
        return render_template('home.html', logged_in=False)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form['username']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, password, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

        user_id = user['id']
        role = user['role']
        hashed_password = user['password']

        if not hashed_password.startswith('$2b$'):
            flash('Invalid password format in database.', 'error')
            return render_template('login.html')

        if not bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

        session_id = str(uuid.uuid4())
        payload = {
            'user_id': user_id,
            'role': role,  # ✅ Include role
            'session_id': session_id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=2)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        # ✅ Logging
        logger.info(f"[LOGIN] Token generated for user {user_id} (role: {role}): {token}")
        print(f"[DEBUG] Token: {token}")
        print(f"[DEBUG] Payload: {payload}")

        redis_store[session_id] = sha256(token.encode()).hexdigest()

        response = make_response(redirect(url_for('dashboard')))
        response.set_cookie('token', token, httponly=True, max_age=7200, samesite='Lax')

        return response

    except Exception as e:
        logger.error(f"[LOGIN] Internal server error: {e}", exc_info=True)
        flash('Internal server error.', 'error')
        return render_template('login.html')

    finally:
        cursor.close()
        conn.close()



@app.route('/api/usernames', methods=['GET'])
def api_usernames():
    query = request.args.get('query', '')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username LIKE %s', ('%' + query + '%',))
    usernames = [row[0] for row in cursor.fetchall()]
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
            user_count = cursor.fetchone()[0]
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
        total_books = cursor.fetchone()['total']

        cursor.execute('SELECT COUNT(*) AS total FROM borrowed_books WHERE user_id = %s', (user_id,))
        total_borrowed_books = cursor.fetchone()['total']

        cursor.execute('''
            SELECT b.title, b.author, bb.borrowed_date
            FROM borrowed_books bb
            JOIN books b ON bb.book_id = b.id
            WHERE bb.user_id = %s
        ''', (user_id,))
        borrowed_books_raw = cursor.fetchall()

        borrowed_books = []
        for book in borrowed_books_raw:
            borrowed_date = book.get('borrowed_date')
            book['borrowed_date'] = borrowed_date.strftime('%Y-%m-%d') if borrowed_date else 'N/A'
            borrowed_books.append(book)

        cursor.execute('SELECT username, role FROM users WHERE id = %s', (user_id,))
        user_info = cursor.fetchone()

        username = user_info['username'] if user_info else 'Guest'
        user_role = user_info['role'] if user_info else 'guest'

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

        # ✅ Logging the role from token
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

        hashed_password = generate_password_hash(password, method='bcrypt')

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
    session_id = session.get('session_id')
    if session_id:
        redis_store.delete(session_id)
    session.clear()

    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.delete_cookie('token')
    response.delete_cookie('universal_token')
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
            username = user_result['username'] if user_result else 'Guest'
            user_role = user_result['role'].upper() if user_result else 'USER'

            # Calculate fines for overdue books
            fine_per_day = 10
            current_date = datetime.now().date()

            for book in borrowed_books:
                borrowed_date = book['borrowed_date']
                due_date = book['due_date']

                if isinstance(borrowed_date, datetime):
                    borrowed_date = borrowed_date.date()
                if isinstance(due_date, datetime):
                    due_date = due_date.date()

                overdue_days = max((current_date - due_date).days, 0)
                fine = overdue_days * fine_per_day

                book['borrowed_date'] = borrowed_date
                book['due_date'] = due_date
                book['overdue_days'] = overdue_days
                book['fine'] = fine
                logger.info(f"Calculated overdue days: {overdue_days}, Fine: {fine} for book_id {book['book_id']}")

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
        cursor = conn.cursor()
        cursor.execute('SELECT title, author FROM books WHERE id = %s', (book_id,))
        book = cursor.fetchone()
        cursor.close()
        conn.close()

        if book:
            logger.info(f"Book found: {book}")
            return jsonify({'title': book[0], 'author': book[1]}), 200

        logger.warning(f"Book not found for book_id: {book_id}")
        return jsonify({'message': 'Book not found'}), 404
    except Exception as e:
        logger.error(f"An error occurred while fetching book data: {e}")
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500


# book “master” route
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


socketio = SocketIO(app)


# Notify clients when new books are added
def notify_clients_new_books():
    socketio.emit('new_books', {'message': 'New books have been added!'})


# Route for adding books, with support for Excel file upload
@app.route('/add_books', methods=['GET', 'POST'])
def add_books():
    role = session.get('role')
    if role is None or role.lower() != 'admin':
        flash('You do not have permission to add books.', 'error')
        return redirect(url_for('library'))

    conn = None
    cursor = None

    if request.method == 'POST':
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Handle Excel file upload
            if 'excel_file' in request.files and request.files['excel_file'].filename != '':
                excel_file = request.files['excel_file']
                df = pd.read_excel(excel_file, engine='openpyxl')

                required_columns = ['title', 'author', 'image', 'total_copies']
                if not all(col in df.columns for col in required_columns):
                    flash('Excel file must contain title, author, image, and total_copies columns.', 'error')
                    return redirect(url_for('add_books'))

                for _, row in df.iterrows():
                    title = row['title']
                    author = row['author']
                    image = row['image']
                    total_copies = row['total_copies']

                    if not isinstance(total_copies, int) or total_copies < 1:
                        flash(f"Invalid total copies for '{title}'", 'error')
                        continue

                    cursor.execute('SELECT id FROM books WHERE title = %s AND author = %s', (title, author))
                    existing_book = cursor.fetchone()

                    if existing_book is None:
                        cursor.execute('''
                            INSERT INTO books (title, author, image, total_copies, available_copies)
                            VALUES (%s, %s, %s, %s, %s)
                        ''', (title, author, image, total_copies, total_copies))

                        book_id = cursor.lastrowid

                        for _ in range(total_copies):
                            cursor.execute('INSERT INTO inventory (book_id, status) VALUES (%s, %s)', (book_id, 'available'))

                        flash(f"Book '{title}' by '{author}' added successfully.", 'success')
                    else:
                        flash(f"Book '{title}' by '{author}' already exists. Skipping.", 'info')

                conn.commit()
                notify_clients_new_books()

            # Handle manual book addition
            elif all(field in request.form for field in ('title', 'author', 'total_copies')):
                title = request.form['title']
                author = request.form['author']
                total_copies = int(request.form['total_copies'])
                image_file = request.files.get('image')

                image_filename = image_file.filename if image_file and image_file.filename else 'default.jpg'

                cursor.execute('SELECT id FROM books WHERE title = %s AND author = %s', (title, author))
                existing_book = cursor.fetchone()

                if existing_book is None:
                    cursor.execute('''
                        INSERT INTO books (title, author, image, total_copies, available_copies)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (title, author, image_filename, total_copies, total_copies))

                    book_id = cursor.lastrowid

                    for _ in range(total_copies):
                        cursor.execute('INSERT INTO inventory (book_id, status) VALUES (%s, %s)', (book_id, 'available'))

                    flash(f"Book '{title}' by '{author}' added successfully.", 'success')
                    conn.commit()
                    notify_clients_new_books()
                else:
                    flash(f"Book '{title}' by '{author}' already exists. Skipping.", 'info')

            else:
                flash('Invalid submission. Please fill all required fields.', 'error')

        except Exception as e:
            if conn:
                conn.rollback()
            flash(f'Error: {str(e)}', 'error')

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return redirect(url_for('library'))

    return render_template('add_books.html')



# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


# WebSocket events
@socketio.on('connect')
def handle_connect():
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

def generate_image_filename(title):
    # Normalize and clean up title
    title = unicodedata.normalize('NFKD', title).encode('ascii', 'ignore').decode('ascii')
    title = title.strip().lower()
    title = re.sub(r'[^a-z0-9\s]', '', title)
    filename = re.sub(r'\s+', '_', title)

    # Special series logic
    diary_keywords = [
        "rodrick_rules", "the_last_straw", "dog_days", "the_ugly_truth",
        "cabin_fever", "the_third_wheel", "hard_luck", "the_long_haul",
        "old_school", "double_down", "the_getaway", "the_meltdown",
        "wrecking_ball", "the_deep_end", "big_shot", "diper_overlode", "no_brainer"
    ]

    if "diary_of_a_wimpy_kid" in filename:
        return filename + ".jpg"
    for keyword in diary_keywords:
        if keyword in filename:
            return f"diary_of_a_wimpy_kid_{keyword}.jpg"

    if filename.startswith("five"):
        return f"the_famous_five_{filename}.jpg"

    if filename.startswith("secret_seven"):
        return f"the_secret_seven_{filename}.jpg"

    if re.match(r"[a-z]_is_for_", filename):
        return filename + ".jpg"  # Sue Grafton style

    return filename + ".jpg"  # Default fallback

@app.route('/view_books', methods=['GET'])
@token_required
def view_books(user_id):
    search_query = request.args.get('search', '')

    # Fetch books from the database based on the search query
    def get_books_from_your_db(search_query):
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        try:
            if search_query:
                cursor.execute(
                    "SELECT id, title, author FROM books WHERE title LIKE %s OR author LIKE %s",
                    (f"%{search_query}%", f"%{search_query}%")
                )
            else:
                cursor.execute(
    "SELECT id AS book_id, title, author, total_copies, available_copies FROM books WHERE title LIKE %s OR author LIKE %s",
    (f"%{search_query}%", f"%{search_query}%")
)
            books = cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
        return books

    books = get_books_from_your_db(search_query)

    for book in books:
        book['image_path'] = generate_image_filename(book['title'])

    role = session.get('role')
    is_admin = (role == 'ADMIN')

    return render_template('view_books.html', books=books, search_query=search_query, is_admin=is_admin)








# Deleting books route
@app.route('/delete_books', methods=['POST'])
@token_required
def delete_books(user_id):
    role = session.get('role')

    # Only admins are allowed to delete books
    if role != 'ADMIN':
        flash('You do not have permission to delete books.', 'error')
        return redirect(url_for('view_books'))

    # Get selected book IDs from the form
    book_ids = request.form.getlist('book_ids[]')

    if not book_ids:
        flash('No books selected for deletion.', 'error')
        return redirect(url_for('view_books'))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        for book_id in book_ids:
            if not book_id.isdigit():
                flash(f'Invalid book ID: {book_id}', 'error')
                continue

            book_id = int(book_id)

            # Check the current available copies for the book
            cursor.execute('SELECT available_copies, total_copies FROM books WHERE id = %s', (book_id,))
            book = cursor.fetchone()

            if book:
                available_copies = book['available_copies']
                total_copies = book['total_copies']

                # If there are available copies, decrement the count
                if available_copies > 0:
                    new_available_copies = available_copies - 1
                    cursor.execute('UPDATE books SET available_copies = %s WHERE id = %s',
                                   (new_available_copies, book_id))

                    # Optional: If no copies remain, delete the book from inventory
                    if new_available_copies == 0 and total_copies == 1:
                        cursor.execute('DELETE FROM inventory WHERE book_id = %s', (book_id,))
                        cursor.execute('DELETE FROM books WHERE id = %s', (book_id,))

                    conn.commit()
                else:
                    flash(f'No available copies left for book ID: {book_id}', 'error')
            else:
                flash(f'Book ID {book_id} not found in the database.', 'error')

        flash('Selected books updated successfully.', 'success')

    except pymysql.MySQLError as e:
        if conn:
            conn.rollback()
        flash(f'An error occurred: {e}', 'error')
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(url_for('library'))



def is_book_available(book_id):
    """Check if the book is available."""
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT available FROM books WHERE id = %s", (book_id,))
            result = cursor.fetchone() # 
            if result:
                return result['available']
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
            cursor = conn.cursor(pymysql.cursors.DictCursor)

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
                if result and result['borrow_count'] >= 1:
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
                book['image_path'] = generate_image_filename(book['title'])

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


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
