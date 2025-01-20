from flask import Flask, render_template, request, flash, redirect, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vms.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

db = SQLAlchemy(app)

# custom filter to format date
@app.template_filter('format_datetime')
def format_datetime(value):
    if isinstance(value, str):
        return datetime.strptime(value, "%Y-%m-%dT%H:%M").strftime("%b %d, %Y %I:%M %p")
    return value

# user table in database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')

# visit logs table in database
class visit_logs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    contact = db.Column(db.String(15), nullable=False)
    purpose = db.Column(db.String(255), nullable=False)
    toMeet = db.Column(db.String(255), nullable=False)
    checkIn = db.Column(db.String(100), nullable=False)
    checkOut = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# visit logs table in database
class Notifications(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(100), nullable=False)
    isRead = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # check if has empty fields 
        if not name or not email or not password:
            flash('Please fill out all fields!', 'error')
            return redirect(url_for('register'))

        # hashed password for security
        hashed_password = generate_password_hash(password)

        # check if email already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))

        # if not registered insert user data to database
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        # check if credentials entered is correct
        if not user or not check_password_hash(user.password, password):
            flash('Invalid login credentials!', 'error')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        session['user_name'] = user.name
        session['user_role'] = user.role
        
        # check if user is admin or not and redirects them to their side
        if user.role == 'user':
            return redirect(url_for('home'))  
        else:
            return redirect(url_for('admin'))  


    return render_template('login.html')

# home route
@app.route('/home')
def home():
    if 'user_id' not in session:
        flash('You need to log in to access this page!', 'error')
        return redirect(url_for('login'))

    return render_template('Home.html')

# history route
@app.route('/history', methods=['GET', 'POST'])
def history():
    if 'user_id' not in session:
        flash('You need to log in to access this page!', 'error')
        return redirect(url_for('login'))

    userID = session.get('user_id')

    # check out method 
    if request.method == 'POST':
        userId = session.get('user_id')
        log_id = request.form.get('log_id')
        checkOutDateTime = request.form.get('checkedOut')

        log = visit_logs.query.filter_by(id=log_id, user_id=userID).first()
        if log:
            log.checkOut = checkOutDateTime
            db.session.commit() 
            flash('Check out successfully!', 'success')
        else:
            flash('Log not found or you do not have permission to update it.', 'error')

        # inserts notifications data to database
        new_notification = Notifications(message='Visitor Checkout Complete!', user_id=userId)
        db.session.add(new_notification)
        db.session.commit()

    logs = visit_logs.query.filter(visit_logs.user_id == userID).order_by(desc(visit_logs.checkIn)).all()

    return render_template('History.html', logs=logs)
 
# check in route
@app.route('/check-in', methods=['GET', 'POST'])
def checkin():
    # if method is post insert data to data base
    if request.method == 'POST':
        name = request.form.get('name')
        gender = request.form.get('gender')
        age = request.form.get('age')
        contact = request.form.get('contact')
        purpose = request.form.get('purpose')
        toMeet = request.form.get('toMeet')
        checkIn = request.form.get('checkIn')
        userId = session.get('user_id')

        # checks if has empty fields
        if not name or not gender or not age or not contact or not purpose or not toMeet or not checkIn:
            flash('Please fill out all fields!', 'error')
            return redirect(url_for('checkin'))

        # inserts data to database
        new_visit = visit_logs(name=name, gender=gender, age=age, contact=contact, purpose=purpose, toMeet=toMeet, checkIn=checkIn, user_id=userId)
        db.session.add(new_visit)
        db.session.commit()

        # inserts notifications data to database
        new_notification = Notifications(message='New Visitor Alert!', user_id=userId)
        db.session.add(new_notification)
        db.session.commit()

        flash('Checked In Successfully!', 'success')
        return redirect(url_for('checkin'))

    userName = session.get('user_name')

    return render_template('CheckIn.html', userName=userName)

#admin dashboard route
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session:
        flash('You need to log in to access this page!', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        log = visit_logs.query.get(request.form.get('log_id'))
        db.session.delete(log)
        db.session.commit()
        flash('Deleted log successfully!', 'success')

    logs = visit_logs.query.order_by(desc(visit_logs.checkIn)).all()

    return render_template('Admin.html', logs=logs)

@app.route('/notifications', methods=['GET', 'POST'])
def notifications():
    if 'user_id' not in session:
        flash('You need to log in to access this page!', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        log = Notifications.query.get(request.form.get('notif_id'))
        db.session.delete(log)
        db.session.commit()
        flash('Deleted notifications successfully!', 'success')

    notifications = Notifications.query.all()

    return render_template('Notifications.html', notifications=notifications)

# generate csv
@app.route('/download-csv')
def download_csv():
    logs = visit_logs.query.all()

    csv_data = [
        {
            "Name": log.name,
            "Gender": log.gender,
            "Age": log.age,
            "Contact": log.contact,
            "Purpose": log.purpose,
            "Visited Student": log.toMeet,
            "Checked-in": log.checkIn,
            "Checked-out": log.checkOut,
        }
        for log in logs
    ]

    def generate_csv():
        yield ",".join(csv_data[0].keys()) + "\n" 
        for row in csv_data:
            yield ",".join(str(value) for value in row.values()) + "\n"

    return Response(
        generate_csv(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=history_logs.csv"}
    )

# logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Create tables only if they don't exist (manual check)
def create_tables():
    with app.app_context():
        if not os.path.exists('vms.db'):
            db.create_all()

create_tables()

if __name__ == '__main__':
    app.run(debug=True)
