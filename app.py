from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users2.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] =True
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@app.route('/')
def index():
    print(session) 
    return render_template('main_page.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username  # Set the username in the session
            return redirect(url_for('main_page'))
        # If authentication fails, you can add an error message here
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')


@app.route('/main_page')
def main_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = session.get('username', 'Guest')  # This should now work correctly
    return render_template('user.html', username=username)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Input validation
        if not username or not password or not confirm_password:
            flash('Please fill out all fields', 'warning')
            return render_template('register.html')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('register.html')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        # Password strength check (example: at least one number and one uppercase letter)
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
            flash('Password must be at least 8 characters long, include a number, and an uppercase letter', 'error')
            return render_template('register.html')

        # If all checks pass, proceed to create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    else:
        # Render the registration page for GET requests
        return render_template('register.html')

@app.route('/logout')
def logout():
    # Remove 'user_id' from session
    session.pop('user_id', None)
    # Redirect to login page or home page after logout
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.run(host= '10.14.13.171', port=8855, debug=False)
