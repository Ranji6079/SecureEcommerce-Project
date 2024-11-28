from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory, abort, send_file
import sqlite3
import os
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import ast
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
app = Flask(__name__)
app.secret_key = os.urandom(24)
from werkzeug.utils import secure_filename

# Initialize the Flask app with static folder configuration
app = Flask(__name__, static_folder='static')
# Set a secret key for the app
app.secret_key = 'dynrhn57hsyhsi8' 
# Email settings
sender_email = "codeflux001@gmail.com"
app_password = "tskt qivl uece vbjb "
admin_email = "codeflux001@gmail.com"

# Code storage directory
code_storage_dir = os.path.join(os.path.dirname(__file__), 'code-storage')
os.makedirs(code_storage_dir, exist_ok=True)  # Ensure directory exists

# Define the folder to save profile pictures
UPLOAD_FOLDER = 'static/images/profile_pictures'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Dataset storage directory
uploaded_file_dir = os.path.join(os.path.dirname(__file__), 'datasets')
app.config['ALLOWED_EXTENSIONS'] = {'csv', 'json', 'txt'}
# Check if the uploaded file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Track failed login attempts
failed_attempts = {}

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            dob DATE,
            country TEXT,
            profile_picture TEXT,
            otp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def send_alert_email():
    try:
        msg = MIMEText("Dear admin, Your system has received attempted hack! Stay on High Alert!")
        msg['Subject'] = "Security Alert: Login Attempts Exceeded"
        msg['From'] = sender_email
        msg['To'] = admin_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.sendmail(sender_email, admin_email, msg.as_string())
        server.quit()
        print("Alert email sent successfully!")
    except Exception as e:
        print(f"Error sending alert email: {e}")

def send_otp(email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = "Your Code Flux OTP"
        body = f"Dear User, Welcome to Codeflux🤝! Your OTP code is: {otp}"
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        print("OTP email sent successfully!")
    except Exception as e:
        print(f"Error sending OTP email: {e}")
# Index route for launching the app
@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('home_page'))  # Redirect to home if logged in
    return render_template('index.html')  # Render index.html for guests

# Resources route
@app.route('/resources')
def resources():
    # Render the Resources page directly
    return render_template('resources.html')

# Privacy Policy route
@app.route('/privacy')
def privacy():
    # Render the Privacy Policy page directly
    return render_template('privacy.html')

# Terms of Service route
@app.route('/terms')
def terms():
    # Render the Terms of Service page directly
    return render_template('terms.html')

# Home route
@app.route('/home')
def home_page():
    email = session.get('email')
    if email:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT username, email, first_name, last_name, dob, country, profile_picture FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        
        if user:
            user_data = {
                'username': user[0],
                'email': user[1],
                'first_name': user[2],
                'last_name': user[3],
                'dob': user[4],
                'country': user[5],
                'profile_picture': user[6]  # This should match the filename
            }
            # Adjusting the URL generation to point to the correct directory
            profile_picture_url = url_for('static', filename='images/profile_pictures/' + user[6]) if user[6] else None
            print(f"Profile Picture URL: {profile_picture_url}")  # Log the generated URL
            return render_template('home.html', user=user_data)
    
    flash("You need to log in first.")
    return redirect(url_for('login'))

# security route
@app.route('/security')
def security():
    # Check if the user is logged in
    if 'logged_in' not in session:
        # Redirect to login page if not logged in
        flash("Please log in to access the Security page.")
        return redirect(url_for('login'))
    # If logged in, render the Security page
    return render_template('security.html')

# about route
@app.route('/about')
def about():
    # Check if the user is logged in
    if 'logged_in' not in session:
        # If not logged in, redirect to the login page
        flash("Please log in to access the About page.")
        return redirect(url_for('login'))
    
    # If logged in, proceed to the About page
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    global failed_attempts
    
    if request.method == 'POST':
        email = request.form['email']  # Accept email for login
        password = request.form['password']
        role = request.form['role']  # Accept role information
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Check if the email and password are valid
        c.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
        user = c.fetchone()
        conn.close()
        
        if user:
            failed_attempts[email] = 0  # Reset attempts after successful login
            
            otp = str(random.randint(100000, 999999))
            send_otp(email, otp)  # Send OTP to user's email
            
            # Update OTP in the database
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("UPDATE users SET otp = ? WHERE email = ?", (otp, email))
            conn.commit()
            conn.close()
            
            session['email'] = email
            session['role'] = role  # Store the user's role in the session
            
            # Redirect to OTP verification instead of directly to the role-specific page
            return redirect(url_for('verify_otp'))  # Go to OTP verification page

        else:
            failed_attempts[email] = failed_attempts.get(email, 0) + 1
            if failed_attempts[email] == 4:
                send_alert_email()
            flash("Invalid credentials, please try again.")
    
    return render_template('login.html')

# verify otp route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        email = session.get('email')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ? AND otp = ?", (email, otp))
        user = c.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            return redirect(url_for('home_page'))
        else:
            flash("Incorrect OTP, please try again.")
            return redirect(url_for('login'))
    return render_template('verify_otp.html')

# register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username or email already exists. Please try a different one.")
            return redirect(url_for('register'))
        finally:
            conn.close()
        
        otp = str(random.randint(100000, 999999))
        send_otp(email, otp)  # Send OTP for registration verification
        
        # Save OTP in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET otp = ? WHERE email = ?", (otp, email))
        conn.commit()
        conn.close()
        
        session['email'] = email
        flash("Registration successful! Please verify your OTP.")
        return redirect(url_for('verify_otp'))
    
    return render_template('registration.html')
# Route to update user profile
@app.route('/update_profile', methods=['POST'])
def update_profile():
    email = session.get('email')  # Get the user's email from the session
    if email:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        dob = request.form['dob']
        country = request.form['country']
        
        # Handle profile picture upload
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture and profile_picture.filename != '':
                filename = secure_filename(profile_picture.filename)
                profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            else:
                filename = None
        else:
            filename = None
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Update user details
        c.execute("""
            UPDATE users 
            SET first_name = ?, last_name = ?, dob = ?, country = ?, profile_picture = ?
            WHERE email = ?
        """, (first_name, last_name, dob, country, filename, email))
        conn.commit()
        conn.close()
        
        flash("Profile updated successfully!")
        return redirect(url_for('home_page'))
    
    flash("You need to log in first.")
    return redirect(url_for('login'))  # Redirect to login if not logged in

# Serializer for generating and decoding tokens
s = URLSafeTimedSerializer(app.secret_key)
# Email settings
sender_email = "codeflux001@gmail.com"
app_password = "tskt qivl uece vbjb"  # Ensure there are no extra spaces here
admin_email = "codeflux001@gmail.com"

# Send email link for reset password
def send_email(subject, recipient, body):
    """Sends an email for password reset."""
    try:
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))  # Attach the email body content
        
        # Initialize SMTP server with SSL
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, app_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        
        print("Password reset email sent successfully!")
    except Exception as e:
        print(f"Error sending password reset email: {e}")
# Forgot Password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Check if user exists in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        
        if user:
            # Generate a secure token for the reset link
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            email_body = f'Click the link to reset your password: {reset_url}'
            
            # Send the reset email
            send_email('Password Reset Request', email, email_body)
            flash('A password reset link has been sent to your email.', 'info')
            return render_template('forgot_password_success.html')
        else:
            flash('No account found with that email.', 'danger')
    
    return render_template('forgot_password.html')

# Reset Password route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode the token to get the email
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        # Update the user's password in the database, storing it as a hash
        hashed_password = generate_password_hash(new_password)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        conn.close()
        
        flash('Your password has been reset successfully.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)
# Quiz route
@app.route('/quiz')
def quiz():
    return render_template('quiz.html')  # Serve the quiz HTML

# Programming route
@app.route('/programming')
def programming():
    return render_template('programming.html')

# Pdfs routes
# Define the path to PDFs within the templates folder
PDF_DIRECTORY = os.path.join(app.root_path, 'templates', 'pdf')
@app.route('/pdfs/<path:filename>')
def serve_pdf(filename):
    try:
        return send_file(os.path.join(PDF_DIRECTORY, filename), mimetype='application/pdf')
    except FileNotFoundError:
        abort(404)
#-----------------------------programing quiz-------------------------------------------------------------------
# Questions for Python, Java, and C++
questions = {
    'python': [
        {"question": "What will this code output? print(2 + 2)", "correct_answer": "4"},
        {"question": "What will this code output? print(10 / 2)", "correct_answer": "5.0"},
        {"question": "What will this code output? print(3 * 3)", "correct_answer": "9"},
        {"question": "What will this code output? print(10 // 3)", "correct_answer": "3"},
        {"question": "What will this code output? print('Hello'.upper())", "correct_answer": "HELLO"},
        {"question": "What will this code output? print('Python'[-1])", "correct_answer": "n"},
        {"question": "What will this code output? print(len([1, 2, 3]))", "correct_answer": "3"},
        {"question": "What will this code output? print(10 % 3)", "correct_answer": "1"}
    ],
    'java': [
        {"question": "What will this code output? System.out.println(2 + 2);", "correct_answer": "4"},
        {"question": "What will this code output? System.out.println(10 / 2);", "correct_answer": "5"},
        {"question": "What will this code output? System.out.println(3 * 3);", "correct_answer": "9"},
        {"question": "What will this code output? System.out.println(10 / 3);", "correct_answer": "3"},
        {"question": "What will this code output? System.out.println('Hello'.toUpperCase());", "correct_answer": "HELLO"},
        {"question": "What will this code output? System.out.println('Java'.charAt(0));", "correct_answer": "J"},
        {"question": "What will this code output? System.out.println(Arrays.asList(1, 2, 3).size());", "correct_answer": "3"},
        {"question": "What will this code output? System.out.println(10 % 3);", "correct_answer": "1"}
    ],
    'cpp': [
        {"question": "What will this code output? std::cout << 2 + 2 << std::endl;", "correct_answer": "4"},
        {"question": "What will this code output? std::cout << 10 / 2 << std::endl;", "correct_answer": "5"},
        {"question": "What will this code output? std::cout << 3 * 3 << std::endl;", "correct_answer": "9"},
        {"question": "What will this code output? std::cout << 10 / 3 << std::endl;", "correct_answer": "3"},
        {"question": "What will this code output? std::cout << 'Hello' << std::endl;", "correct_answer": "Hello"},
        {"question": "What will this code output? std::cout << 'C++' << std::endl;", "correct_answer": "C++"},
        {"question": "What will this code output? std::cout << sizeof(int) << std::endl;", "correct_answer": "4"},
        {"question": "What will this code output? std::cout << 10 % 3 << std::endl;", "correct_answer": "1"}
    ]
}

@app.route('/programmingquiz')
def server_programming_quiz():
    # Serving the renamed HTML file 'programmingquiz.html'
    return send_from_directory(os.path.join(os.getcwd(), 'templates'), 'programmingquiz.html')

@app.route('/get_questions/<language>', methods=['GET'])
def get_questions(language):
    # Check if the language is valid
    if language not in questions:
        return jsonify({'error': 'Invalid language'}), 400
    
    # Return the questions for the selected language
    return jsonify({'questions': questions[language]})

@app.route('/check_answer', methods=['POST'])
def check_answer():
    data = request.get_json()
    question_id = data.get('question_id')
    user_answer = data.get('user_answer')
    language = data.get('language')
    
    correct_answer = questions[language][question_id]['correct_answer']
    result = (user_answer.strip() == correct_answer.strip())
    
    return jsonify({'correct': result, 'correct_answer': correct_answer})

@app.route('/grade', methods=['POST'])
def grade():
    data = request.get_json()
    answers = data.get('answers')  # List of answers for all questions
    language = data.get('language')
    
    grade = 0
    total_questions = len(questions[language])
    
    # Grade calculation
    for idx, answer in enumerate(answers):
        if answer == questions[language][idx]['correct_answer']:
            grade += 1
    
    return jsonify({'grade': grade, 'total_questions': total_questions})
#-----------------------------------end of programming quiz quiz------------------------------#
# Logout route        
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('logged_in', None)
    return redirect(url_for('login'))

# mlai tutorials route
@app.route('/mlai')
def cloud_computing_page():
    # Check if the user is logged in
    if 'logged_in' not in session:
        # Redirect to login page if not logged in
        flash("Please log in to access the mlai page.")
        return redirect(url_for('login'))

    # If logged in, render the mlai page
    return render_template('mlai.html')
# Compiler route
@app.route('/compiler')
def compiler():
    return render_template('compiler.html')

# Compiler functionality with file upload
@app.route('/compile', methods=['POST'])
def compile_code():
    code = request.form.get('code')
    language = request.form.get('language')
    dataset = request.files.get('dataset')  # This will get the file

    file_path, compile_command, run_command = None, None, None

    if language == 'python':
        file_path = os.path.join(code_storage_dir, 'main.py')
        with open(file_path, 'w') as f:
            f.write(code)
        run_command = f'python {file_path}'
        
        required_libraries = detect_imports(code)
        install_libraries(required_libraries)

    elif language == 'java':
        file_path = os.path.join(code_storage_dir, 'Main.java')
        with open(file_path, 'w') as f:
            f.write(code)
        compile_command = f'javac {file_path}'
        run_command = f'java -cp {code_storage_dir} Main'

    elif language == 'cpp':
        file_path = os.path.join(code_storage_dir, 'main.cpp')
        with open(file_path, 'w') as f:
            f.write(code)
        compile_command = f'g++ {file_path} -o {code_storage_dir}/main'
        run_command = f'{code_storage_dir}/main'

    else:
        return jsonify({'output': 'Invalid language selected.'})

    # Handle file (dataset) processing if it's provided
    if dataset:
        if allowed_file(dataset.filename):
            filename = secure_filename(dataset.filename)
            dataset_path = os.path.join(uploaded_file_dir, filename)
            dataset.save(dataset_path)  # Save the file

        else:
            return jsonify({'output': 'Invalid file type. Allowed types are: csv, json, txt.'})

    if compile_command:
        compile_process = subprocess.run(
            compile_command, shell=True, text=True, capture_output=True
        )
        if compile_process.returncode != 0:
            return jsonify({'output': compile_process.stderr})

    run_process = subprocess.run(
        run_command, shell=True, text=True, capture_output=True
    )
    output = run_process.stdout if run_process.returncode == 0 else run_process.stderr

    return jsonify({'output': output})


@app.route('/get_code/<language>', methods=['GET'])
def get_code(language):
    code_files = {
        'python': 'main.py',
        'java': 'Main.java',
        'cpp': 'main.cpp'
    }

    if language in code_files:
        try:
            file_path = os.path.join(code_storage_dir, code_files[language])
            with open(file_path, 'r') as f:
                code = f.read()
            return jsonify({'code': code})
        except FileNotFoundError:
            return jsonify({'code': 'Code file not found for the selected language.'}), 404
    else:
        return jsonify({'code': 'Invalid language selected.'}), 400

def detect_imports(code):
    tree = ast.parse(code)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            imports.add(node.module)
    return imports - {"calendar"}  # Skip standard libraries like 'calendar'

def install_libraries(libraries):
    for library in libraries:
        try:
            if library in {"calendar"}:
                continue
            subprocess.run(['pip', 'install', library], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error installing {library}: {e}")
if __name__ == '__main__':
    init_db()
    app.run()
