import base64
import logging
import os
import urllib.request
from datetime import date, datetime, timedelta
from functools import wraps
from hashlib import sha256
from logging.handlers import RotatingFileHandler
from uuid import uuid4

import flask_socketio
import flask_sqlalchemy
import jwt
import mysql.connector
import pandas as pd
import psycopg2
import pymysql
import pymysql.cursors
from flask import (Flask, abort, flash, jsonify, make_response, redirect,
                   render_template, request, session, url_for)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_redis import FlaskRedis
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from psycopg2 import DatabaseError, ProgrammingError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

os.environ['FLASK_ENV'] = 'development'

app = Flask(__name__)
app.secret_key = 'your_secret_key'
CORS(app)


app = Flask(__name__, static_folder='static')

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345678'
app.config['MYSQL_DB'] = 'library'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Replace it with your JWT secret key
app.config['UNIVERSAL_SECRET_KEY'] = 'your_universal_secret_key'  # Replace it with your Universal secret key
app.config['SECRET_KEY'] = 'your-super-secret-key'
app.config['REDIS_URL'] = 'redis://localhost:6379/0'  # Replace it with your Redis URL



def image_to_base64(image_filename):
    if image_filename is None:
        return None

    absolute_path = os.path.join(app.root_path, 'static', 'images', image_filename)
    try:
        with open(absolute_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')
    except FileNotFoundError:
        return None
    

redis_store = FlaskRedis(app)

# Set the upload folder for storing images
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'static', 'images')

# Optionally, you can also limit the allowed file extensions
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}



# Configure MySQL connection
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '12345678',
    'database': 'library'
}

# Database connection settings
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='12345678',
    db='library',
    cursorclass=pymysql.cursors.DictCursor
)

# Configure logging
log_handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
log_handler.setFormatter(log_formatter)

logger = logging.getLogger('tdm')
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.DEBUG)  # Set logging level to DEBUG
logger = logging.getLogger(__name__)
app.logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)



def get_db_connection():
    return pymysql.connect(
        host='localhost',
        user='root',
        password='12345678',
        db='library',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


def get_db():
    conn = mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    try:
        # Begin transaction for the users table
        conn.start_transaction()
        cursor.execute(f'CREATE DATABASE IF NOT EXISTS {app.config["MYSQL_DB"]}')
        cursor.execute(f'USE {app.config["MYSQL_DB"]}')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                full_name VARCHAR(50),
                sex ENUM('M', 'F'),
                mobile_number VARCHAR(15),
                country_code VARCHAR(5)
            )
        ''')
        conn.commit()  # Commit transaction for users table

        # Begin transaction for the books table
        conn.start_transaction()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS books (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                author VARCHAR(255) NOT NULL,
                available BOOLEAN DEFAULT TRUE
            )
        ''')
        conn.commit()  # Commit transaction for books table

        # Begin transaction for the borrowed_books table
        conn.start_transaction()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS borrowed_books (
                id INT AUTO_INCREMENT PRIMARY KEY,
                book_id INT NOT NULL,
                user_id INT NOT NULL,
                borrowed_date DATETIME NOT NULL,
                borrow_count INT DEFAULT 0,  -- Adding borrow_count column
                due_date DATETIME,  -- Adding due_date column
                FOREIGN KEY (book_id) REFERENCES books(id)

            )
        ''')
        conn.commit()  # Commit transaction for borrowed_books table

        # Begin transaction for the inventory table
        conn.start_transaction()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inventory (
                id INT AUTO_INCREMENT PRIMARY KEY,
                book_id INT,
                status ENUM('available', 'borrowed') NOT NULL DEFAULT 'available',
                FOREIGN KEY (book_id) REFERENCES books(id)
            )
        ''')
        conn.commit()  # Commit the transaction for the inventory table
        print("Inventory table created successfully.")

    except pymysql.MySQLError as e:
        conn.rollback()  # Rollback if there was an error
        print(f"Error occurred: {e}")

    finally:
        cursor.close()
        conn.close()


# home route
@app.route('/')
def home():
    token = request.cookies.get('token')
    if token:
        return render_template('home.html', logged_in=True)
    else:
        return render_template('home.html', logged_in=False)


# login route
@app.route('/login', methods=['POST', 'GET'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            logger.warning('Missing username or password in request body')
            return jsonify({'message': 'Missing username or password in request body!'}), 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT id, password, role FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if user and check_password_hash(user[1], password):
            user_id = user[0]
            role = user[2]
            session_id = str(uuid4())

            # Create JWT token and universal token
            token = jwt.encode({
                'user_id': user_id,
                'session_id': session_id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config['JWT_SECRET_KEY'], algorithm='HS256')

            universal_token = jwt.encode({
                'user_id': user_id,
                'exp': datetime.utcnow() + timedelta(days=2)
            }, app.config['UNIVERSAL_SECRET_KEY'], algorithm='HS256')

            # Log tokens for debugging
            logger.info(f'Token: {token}')
            logger.info(f'Universal Token: {universal_token}')

            # Store session ID and token hash in Redis
            token_hash = sha256(token.encode()).hexdigest()
            redis_store.setex(session_id, timedelta(hours=2), token_hash)

            # Store session ID, user ID, and role in the session
            session['session_id'] = session_id
            session['user_id'] = user_id
            session['role'] = role  # Ensure role is set in the session

            # Create response with tokens as cookies
            response = make_response(jsonify({'token': token}))
            response.set_cookie('token', token, httponly=True, secure=True)
            response.set_cookie('universal_token', universal_token, httponly=True, secure=True)

            return response

        logger.warning('Invalid credentials provided')
        return jsonify({'message': 'Invalid credentials'}), 403

    # GET method: Fetch all usernames to suggest on login page
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users')
    usernames = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()

    return render_template('login.html', usernames=usernames)



@app.route('/api/usernames', methods=['GET'])
def api_usernames():
    query = request.args.get('query', '')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE username LIKE %s', ('%' + query + '%',))
    usernames = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return jsonify(usernames)
    

# registration route
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        data = request.form.to_dict()

        # Check if required fields are present
        if not data or 'username' not in data or 'email' not in data or 'full_name' not in data \
                or 'sex' not in data or 'mobile_number' not in data or 'country_code' not in data \
                or 'password' not in data or 'confirm_password' not in data:
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

        # Check if passwords match
        if password != confirm_password:
            logger.warning('Passwords do not match')
            return render_template('register.html', data=data, error='Passwords do not match!')

        # Check password complexity
        if not is_complex_password(password):
            logger.warning('Password does not meet complexity requirements')
            return render_template('register.html', data=data, error='Password does not meet complexity requirements!')

        hashed_password = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()

        try:
            # Begin transaction
            conn.start_transaction()

            # Check if this is the first user being registered, if so, make them an admin
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
            role = 'admin' if user_count == 0 else 'user'

            cursor.execute('''
                INSERT INTO users (username, email, password, full_name, sex, mobile_number, country_code, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (username, email, hashed_password, full_name, sex, mobile_number, country_code, role))

            # Commit transaction
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
        return redirect(url_for('login'))  # Redirect to login page after successful registration

    # On GET request, render the registration form with empty fields
    return render_template('register.html', data={})

# token used in verification
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        # Check for both tokens
        token = request.cookies.get('token')
        universal_token = request.cookies.get('universal_token')

        if not token and not universal_token:
            logger.warning('Both tokens are missing')
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            if token:
                data = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
                session_id = data.get('session_id')
                token_hash = redis_store.get(session_id)

                if not token_hash or token_hash.decode() != sha256(token.encode()).hexdigest():
                    logger.warning('Invalid or expired session')
                    return jsonify({'message': 'Invalid or expired session!'}), 401

                user_id = data['user_id']

            elif universal_token:
                data = jwt.decode(universal_token, app.config['UNIVERSAL_SECRET_KEY'], algorithms=['HS256'])
                user_id = data['user_id']

        except jwt.ExpiredSignatureError:
            logger.warning('Token has expired')
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            logger.warning('Invalid token')
            return jsonify({'message': 'Invalid token!'}), 401

        return f(user_id, *args, **kwargs)

    return decorator






# Dashboard route
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    try:
        logger.debug('Fetching total number of books...')
        cursor.execute('SELECT COUNT(*) AS total FROM books')
        total_books = cursor.fetchone()['total']
        logger.debug(f'Total books: {total_books}')

        logger.debug('Fetching total borrowed books for user...')
        cursor.execute('SELECT COUNT(*) AS total FROM borrowed_books WHERE user_id = %s', (user_id,))
        total_borrowed_books = cursor.fetchone()['total']
        logger.debug(f'Total borrowed books: {total_borrowed_books}')

        logger.debug('Fetching borrowed books data...')
        cursor.execute('''
            SELECT b.title, b.author, bb.borrowed_date
            FROM borrowed_books bb
            JOIN books b ON bb.book_id = b.id
            WHERE bb.user_id = %s
        ''', (user_id,))
        borrowed_books = cursor.fetchall()
        logger.debug(f'Borrowed books data: {borrowed_books}')

        logger.debug('Fetching user role...')
        cursor.execute('SELECT role FROM users WHERE id = %s', (user_id,))
        user_role = cursor.fetchone()['role']
        logger.debug(f'User role: {user_role}')

    except Exception as e:
        logger.error(f'An error occurred while fetching dashboard data: {e}')
        flash('An error occurred while fetching dashboard data.', 'error')
        borrowed_books = []
        total_books = 0
        total_borrowed_books = 0
        user_role = 'guest'

    finally:
        cursor.close()
        conn.close()

    dashboard_data = {
        'total_books': total_books,
        'total_borrowed_books': total_borrowed_books,
        'borrowed_books': borrowed_books,
        'user_role': user_role
    }

    # Debug logging to check what data is being sent to the template
    logger.debug(f'Dashboard data being sent to template: {dashboard_data}')

    return render_template('dashboard.html', data=dashboard_data)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        # Extract form data
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        country_code = request.form['country_code']
        role = request.form['role']

        # Hash the password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Insert the user into the database
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                'INSERT INTO users (full_name, username, password, email, mobile_number, country_code, role) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (full_name, username, hashed_password, email, phone, country_code, role)
            )
            connection.commit()
            flash('User added successfully!', 'success')
            logger.debug("User added successfully with status code 200")
        except Exception as e:
            connection.rollback()
            flash(f'Error adding user: {str(e)}', 'danger')
            logger.error(f"Error adding user: {e}", exc_info=True)
            return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500
        finally:
            cursor.close()
            connection.close()

        return redirect(url_for('add_user'))

    return render_template('add_user.html')



@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user():
    # Check if the user is an admin (role check)
    if 'role' in session and session['role'] == 'admin':
        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            # Fetch users from the database, including the 'full_name' column
            cursor.execute("SELECT id, username, full_name FROM users")  
            users = cursor.fetchall()
        except Exception as e:
            flash(f'Error fetching users: {str(e)}', 'danger')
            users = []
        finally:
            cursor.close()
            connection.close()

        if request.method == 'POST':
            user_id = request.form.get('user_id')
            if user_id:
                connection = get_db_connection()
                cursor = connection.cursor()
                try:
                    # Delete the user by ID
                    cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
                    connection.commit()
                    flash("User deleted successfully!", "success")
                except Exception as e:
                    connection.rollback()
                    flash(f"Error deleting user: {str(e)}", "danger")
                finally:
                    cursor.close()
                    connection.close()
                return redirect(url_for('delete_user'))

        return render_template('delete_user.html', users=users)
    else:
        flash("Access denied!", "danger")
        return redirect(url_for('dashboard'))






# viewing profile route
@app.route('/profile', methods=['GET'])
@token_required
def profile(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, full_name, sex, mobile_number, country_code FROM users WHERE id = %s',
                   (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    return render_template('profile.html', user=user)

@app.route('/view_users_roster', methods=['GET'])
def view_users_roster():
    if 'role' not in session or session['role'] != 'admin':
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db_connection()  # Ensure the database connection is initialized
    cursor = db.cursor()
    query = "SELECT id, username, full_name, email, mobile_number, country_code, role FROM users"
    cursor.execute(query)
    users = cursor.fetchall()
    db.close()  # Don't forget to close the connection after you're done
    return render_template('users_roster.html', users=users)


# updating profile route
@app.route('/update_profile', methods=['POST'])
@token_required
def update_profile(user_id):
    # Retrieve form data
    full_name = request.form.get('full_name')
    sex = request.form.get('sex')
    mobile_number = request.form.get('mobile_number')
    country_code = request.form.get('country_code')
    email = request.form.get('email')

    # Validate data
    if not all([full_name, sex, mobile_number, country_code, email]):
        return jsonify({'message': 'Missing required fields'}), 400

    conn = get_db()
    cursor = conn.cursor()
    try:
        # Begin transaction
        conn.start_transaction()

        cursor.execute('''
            UPDATE users
            SET full_name = %s, sex = %s, mobile_number = %s, country_code = %s, email = %s
            WHERE id = %s
        ''', (full_name, sex, mobile_number, country_code, email, user_id))

        # Commit transaction
        conn.commit()
    except mysql.connector.Error as e:
        conn.rollback()
        return jsonify({'message': f'Error occurred: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('profile'))


# deleting profile route
@app.route('/profile/delete', methods=['POST'])
@token_required
def delete_profile(user_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Begin transaction
        conn.start_transaction()

        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))

        # Commit transaction
        conn.commit()
    except mysql.connector.Error as e:
        conn.rollback()
        return jsonify({'message': f'Error occurred: {str(e)}'}), 500
    finally:
        cursor.close()
        conn.close()

    # Log out user after deletion
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
        redis_store.delete(session_id)  # Delete token from Redis
    session.clear()  # Clear the session
    
    response = make_response(jsonify({'message': 'Logged out successfully'}))
    response.delete_cookie('token')  # Delete session token cookie
    response.delete_cookie('universal_token')  # Delete universal token cookie
    return response


# library app routes

# library home page route
@app.route('/library')
@token_required
def library(user_id):
    try:
        conn = get_db_connection()
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:  # Use DictCursor here
            # Fetch the total number of books
            cursor.execute("SELECT COUNT(*) AS book_count FROM books")
            result = cursor.fetchone()
            book_count = result['book_count'] if result else 0
            logger.info(f"Total number of books: {book_count}")

            # Fetch borrowed books for the user
            cursor.execute('''
                SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                FROM borrowed_books bb
                JOIN books b ON bb.book_id = b.id
                WHERE bb.user_id = %s
            ''', (user_id,))
            borrowed_books = cursor.fetchall()
            logger.info(f"Borrowed books fetched for user_id {user_id}: {borrowed_books}")

            # Fetch the username for the user_id
            cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
            user_result = cursor.fetchone()
            username = user_result['username'] if user_result else 'Guest'

            # Fine calculation settings
            fine_per_day = 10
            current_date = datetime.now().date()

            # Add overdue days and fine information
            for book in borrowed_books:
                borrowed_date = book['borrowed_date']
                due_date = book['due_date']

                # Ensure the due_date is a date object
                if not isinstance(due_date, date):
                    try:
                        due_date = datetime.strptime(due_date, '%Y-%m-%d').date()
                    except ValueError as e:
                        logger.error(f"Invalid due_date format for book_id {book['book_id']}: {due_date}. Error: {e}")
                        continue

                overdue_days = (current_date - due_date).days if current_date > due_date else 0
                fine = overdue_days * fine_per_day if overdue_days > 0 else 0

                book['overdue_days'] = overdue_days
                book['fine'] = fine

                logger.info(f"Calculated overdue days: {overdue_days}, Fine: {fine} for book_id {book['book_id']}")

    except Exception as e:
        logger.error(f"An error occurred while fetching library data: {e}")
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500

    finally:
        conn.close()

    return render_template('library.html', book_count=book_count, borrowed_books=borrowed_books, user_id=user_id, username=username)



# books route
@app.route('/book/<int:book_id>', methods=['GET'])
@token_required
def book(book_id):
    try:
        conn = get_db()
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

    if role != 'admin':
        flash('You do not have permission to add books.', 'error')
        return redirect(url_for('library'))

    if request.method == 'POST':
        excel_file = request.files.get('excel_file')

        if not excel_file:
            flash('No Excel file uploaded.', 'error')
            return redirect(url_for('add_books'))

        try:
            # Load the Excel file
            df = pd.read_excel(excel_file)

            # Make sure necessary columns are present
            required_columns = ['title', 'author', 'image', 'total_copies']
            if not all(col in df.columns for col in required_columns):
                flash('Excel file must contain title, author, image, and total_copies columns.', 'error')
                return redirect(url_for('add_books'))

            conn = get_db_connection()
            cursor = conn.cursor()

            # Iterate through the DataFrame and add books
            for _, row in df.iterrows():
                title = row['title']
                author = row['author']
                image = row['image']
                total_copies = row['total_copies']

                # Check if the book already exists in the database
                cursor.execute('''
                    SELECT id FROM books WHERE title = %s AND author = %s
                ''', (title, author))
                existing_book = cursor.fetchone()

                if existing_book is None:
                    # Insert book data into the books table with total copies and available copies set to 0 initially
                    cursor.execute('''
                        INSERT INTO books (title, author, image, total_copies, available_copies)
                        VALUES (%s, %s, %s, %s, %s)
                    ''', (title, author, image, total_copies, 0))

                    book_id = cursor.lastrowid

                    # Insert each copy into the inventory table
                    for _ in range(total_copies):
                        cursor.execute('''
                            INSERT INTO inventory (book_id, status)
                            VALUES (%s, 'available')
                        ''', (book_id,))
                    
                    # Update total and available copies in the books table after each addition
                    cursor.execute('''
                        UPDATE books
                        SET total_copies = total_copies + 1, available_copies = available_copies + 1
                        WHERE id = %s
                    ''', (book_id,))

                    flash(f"Book '{title}' by '{author}' added successfully.", 'success')
                else:
                    flash(f"Book '{title}' by '{author}' already exists. Skipping.", 'info')

            conn.commit()

            # Notify clients of new books via WebSocket
            notify_clients_new_books()

        except Exception as e:
            conn.rollback()
            flash(f'Failed to process Excel file: {str(e)}', 'error')

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



@app.route('/view_books', methods=['GET'])
@token_required  # Ensure that you have the token_required decorator to check user authentication
def view_books(user_id):
    search_query = request.args.get('search', '')

    # Establish a database connection
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)

    # SQL Query with optional search filter
    sql_query = """
    SELECT 
        b.id AS book_id,
        b.title,
        b.author,
        COALESCE(bi.image_path, 'default_image.jpg') AS image_path, 
        b.total_copies,
        b.available_copies
    FROM 
        books AS b
    LEFT JOIN 
        book_images AS bi ON b.id = bi.book_id
    WHERE 
        b.title LIKE %s OR b.author LIKE %s
    ORDER BY 
        b.id;
    """
    
    cursor.execute(sql_query, ('%' + search_query + '%', '%' + search_query + '%'))
    books = cursor.fetchall()

    cursor.close()
    connection.close()

    # Check if the user is an admin
    role = session.get('role')  # Retrieve user role from the session
    is_admin = (role == 'admin')

    return render_template('view_books.html', books=books, search_query=search_query, is_admin=is_admin)








# Deleting books route
@app.route('/delete_books', methods=['POST'])
@token_required
def delete_books(user_id):
    role = session.get('role')

    # Only admins are allowed to delete books
    if role != 'admin':
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
                    cursor.execute('UPDATE books SET available_copies = %s WHERE id = %s', (new_available_copies, book_id))

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
            result = cursor.fetchone()
            if result:
                return result['available']
            return False
    except Exception as e:
        logger.error(f"An error occurred while checking availability: {e}")
        return False


# Borrowing books route
@app.route('/borrow', methods=['GET', 'POST'])
@token_required
def borrow_books(user_id):
    search_query = request.args.get('search', '')
    user_id = session.get('user_id')
    role = session.get('role')

    if request.method == 'POST':
        # Get all selected book IDs from the form
        book_ids = request.form.getlist('book_ids[]')  # Expecting multiple book IDs as a list
        # Only prompt for user_id if the role is admin
        target_user_id = request.form.get('user_id') if role == 'admin' else user_id

        # Check if user is logged in
        if not target_user_id:
            flash('You must be logged in to borrow a book.', 'error')
            return redirect(url_for('borrow_books'))

        # Validate that at least one book ID is provided
        if not book_ids or not all(book_id.isdigit() for book_id in book_ids):
            flash('Invalid book ID(s).', 'error')
            return redirect(url_for('borrow_books'))

        # Process each book ID separately
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            for book_id in book_ids:
                book_id = int(book_id)  # Convert to integer
                
                # Check if user has already borrowed a copy of this book
                cursor.execute('''
                    SELECT COUNT(*) as borrow_count 
                    FROM borrowed_books 
                    WHERE book_id = %s AND user_id = %s
                ''', (book_id, target_user_id))
                result = cursor.fetchone()
                borrow_count = result['borrow_count'] if result else 0

                if borrow_count >= 1:
                    flash(f'You have already borrowed a copy of book ID {book_id}.', 'error')
                    continue

                # Check for available copies of the book
                cursor.execute('''
                    SELECT COUNT(*) as available_copies
                    FROM inventory
                    WHERE book_id = %s AND status = 'available'
                ''', (book_id,))
                result = cursor.fetchone()
                available_copies = result['available_copies'] if result else 0

                if available_copies < 1:
                    flash(f'No available copies to borrow for book ID {book_id}.', 'error')
                    continue

                # Borrow one copy of the book
                borrowed_date = datetime.now()
                due_date = borrowed_date + timedelta(days=14)

                cursor.execute('''
                    INSERT INTO borrowed_books (user_id, book_id, borrowed_date, due_date)
                    VALUES (%s, %s, %s, %s)
                ''', (target_user_id, book_id, borrowed_date, due_date))

                # Update the inventory status to 'borrowed'
                cursor.execute('''
                    UPDATE inventory
                    SET status = 'borrowed'
                    WHERE book_id = %s AND status = 'available'
                    LIMIT 1
                ''', (book_id,))

                # Update the total and available copies in the books table
                cursor.execute('''
                    UPDATE books
                    SET available_copies = available_copies - 1
                    WHERE id = %s
                ''', (book_id,))

            conn.commit()
            flash('Selected books borrowed successfully.', 'success')

        except pymysql.MySQLError as e:
            if conn:
                conn.rollback()
            flash(f'An error occurred: {e}', 'error')
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return redirect(url_for('borrow_books'))

    else:
        # Search and fetch available books
        conn = None
        cursor = None
        books = []
        try:
            conn = get_db_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)
            query = '''
                SELECT b.id, b.title, b.author, b.image,
                       COUNT(i.id) AS total_copies,
                       SUM(CASE WHEN i.status = 'available' THEN 1 ELSE 0 END) AS available_copies
                FROM books b
                LEFT JOIN inventory i ON b.id = i.book_id
                WHERE b.title LIKE %s OR b.author LIKE %s OR b.id = %s
                GROUP BY b.id, b.title, b.author, b.image
            '''
            cursor.execute(query, (f'%{search_query}%', f'%{search_query}%', search_query))
            books = cursor.fetchall()
        except pymysql.MySQLError as e:
            logger.error(f"An error occurred while fetching available books: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return render_template('borrow_books.html', books=books, search_query=search_query)









# View borrowed books route
@app.route('/view_borrowed_books', methods=['GET'])
@token_required
def view_borrowed_books(user_id):
    user_id = session.get('user_id')
    role = session.get('role')

    conn = None
    cursor = None
    borrowed_books = []

    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        if role == 'admin':
            # Admin can see all borrowed books and the users who borrowed them
            cursor.execute('''
                SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date, u.username
                FROM borrowed_books bb
                JOIN books b ON bb.book_id = b.id
                JOIN users u ON bb.user_id = u.id
            ''')
        else:
            # Regular user can only see their own borrowed books
            cursor.execute('''
                SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                FROM borrowed_books bb
                JOIN books b ON bb.book_id = b.id
                WHERE bb.user_id = %s
            ''', (user_id,))

        borrowed_books = cursor.fetchall()
        logger.info(f"Borrowed books fetched for user_id {user_id}: {borrowed_books}")

    except pymysql.MySQLError as e:
        logger.error(f"An error occurred while fetching borrowed books: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return render_template('view_borrowed_books.html', borrowed_books=borrowed_books, role=role)



# Route for returning borrowed books
@app.route('/return_books', methods=['GET', 'POST'])
@token_required
def return_books(user_id):
    role = session.get('role')  # Retrieve role from the session

    conn = None
    cursor = None

    if request.method == 'POST':
        book_ids = request.form.getlist('book_ids')  # Get list of selected book IDs
        user_ids = request.form.getlist('user_ids') if role == 'admin' else [user_id] * len(book_ids)

        if not book_ids or not all(id.isdigit() for id in book_ids):
            flash('Invalid book ID(s).', 'error')
            return redirect(url_for('return_books'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor(pymysql.cursors.DictCursor)

            for i, book_id in enumerate(book_ids):
                book_id = int(book_id)
                target_user_id = user_ids[i]  # Use corresponding user ID

                # Check if the book is borrowed by the target user
                cursor.execute('''
                SELECT * FROM borrowed_books
                WHERE book_id = %s AND user_id = %s
            ''', (book_id, target_user_id))
                borrowed_book = cursor.fetchone()

                if not borrowed_book:
                    flash(f'Book {book_id} not found or not borrowed by user {target_user_id}.', 'error')
                continue  # Skip this book if not found

            # Proceed to return the book by deleting the borrowed entry
            cursor.execute('''
                DELETE FROM borrowed_books
                WHERE book_id = %s AND user_id = %s
            ''', (book_id, target_user_id))

            # Update the inventory to set the book's status as available
            cursor.execute('''
                UPDATE inventory
                SET status = 'available'
                WHERE book_id = %s
                LIMIT 1
            ''', (book_id,))

            # Update available_copies in the books table
            cursor.execute('''
                UPDATE books
                SET available_copies = available_copies + 1
                WHERE id = %s
                LIMIT 1
            ''', (book_id,))

            conn.commit()
            flash(f'Successfully returned selected books.', 'success')

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


    # GET method handling: Display list of borrowed books
    try:
        conn = get_db_connection()
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        if role == 'admin':
            # Admin should see all borrowed books by all users
            cursor.execute('''
                SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date, u.id AS user_id, u.username
                FROM borrowed_books bb
                JOIN books b ON bb.book_id = b.id
                JOIN users u ON bb.user_id = u.id
            ''')
        else:
            # Regular user should see only their own borrowed books
            cursor.execute('''
                SELECT b.id AS book_id, b.title, b.author, bb.borrowed_date, bb.due_date
                FROM borrowed_books bb
                JOIN books b ON bb.book_id = b.id
                WHERE bb.user_id = %s
            ''', (user_id,))

        borrowed_books = cursor.fetchall()
    except pymysql.MySQLError as e:
        borrowed_books = []
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