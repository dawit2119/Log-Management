from bson.objectid import ObjectId
# ... other imports ...
import datetime,json
from math import *
from flask import Flask, session,render_template,url_for,redirect,flash,request,jsonify
from flask_login import login_required
from forms import RegistrationForm,LoginForm,AccountUpdateForm
from flask_bcrypt import Bcrypt
from flask_session import Session
from functools import wraps
import logging
from datetime import datetime,timedelta
from bson import ObjectId
import os,secrets,json
from PIL import Image
from database import users_collection,logs_collection
from pymongo import ASCENDING,DESCENDING
from flask_jwt_extended import JWTManager,create_access_token,decode_token
from collections import Counter

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'secret key'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["JWT_SECRET_KEY"] = "3799e7a27e2bb0d7def296bc057b8351a822b42fbcdfb6c6fd1e6d3ab59a3b66"
jwt = JWTManager(app)

Session(app)
logging.basicConfig(level=logging.DEBUG)




@app.route('/log', methods=['POST'])
# @login_required
def log_receiver():
    print("Log data  ap.py",request.json)
    try:
        log_data = request.json

        # Add a timestamp if it's missing
        if 'timestamp' not in log_data or log_data['timestamp'] is None:
            log_data['timestamp'] = datetime.utcnow()

        # Add a default loglevel if it's missing
        if 'loglevel' not in log_data or log_data['loglevel'] is None:
            log_data['loglevel'] = 'INFO'

        # Insert the log into MongoDB
        logs_collection.insert_one(log_data)

        return jsonify({'status': 'success'}), 200

    except json.JSONDecodeError:
        print('error','Invalid JSON format')
        return jsonify({'error': 'Invalid JSON format'}), 400
    except Exception as e:
        print("Exception ",e)
        return jsonify({'error': str(e)}), 500

@app.route("/register", methods=['GET', 'POST'])
def register():
    if session.get("user_id"):
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_data = {
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password
        }
        users_collection.insert_one(user_data)
        flash("Your account is created successfully! You can now log in.", "success")
        return redirect(url_for('index'))
    else:
        print("form is not valid")
    return render_template('register.html', title='Register', form=form)

@app.route("/")
def index():
    return render_template("layout.html",title="home")

@app.route("/about")
def about():
    return render_template("about.html",title="about")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if session.get("user_id"):
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = users_collection.find_one({"email": form.email.data})
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            session['user_id'] = str(user['_id'])  # MongoDB uses ObjectId
            session['username'] = user['username']
            session['email'] = user['email']
            session['image_file'] = user.get('image_file',"")
            expires = timedelta(minutes=10)
            access_token = create_access_token(identity=str(user['_id']), expires_delta=expires)
            # Store the token in session
            session['jwt_token'] = access_token
            flash("You have been logged in!", 'success')
            next_page = request.args.get('next')
            print("next page is ",next_page)
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

def login_required(f):
    #Check Logged in by using session
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please login to access this page!","info")
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
     form = AccountUpdateForm()
     session['username'] = form.username.data
     session['email'] = form.email.data
     user_id = session.get('user_id')
     if form.validate_on_submit():
         update_data = {}
         if form.profile_picture.data:
             profile_picture = save_picture(form.profile_picture.data)
             update_data['image_file'] = profile_picture
         update_data['username'] = form.username.data
         update_data['email'] = form.email.data
         users_collection.update_one({'id':ObjectId(user_id)},{'$set':update_data})
         flash("Your account is updated",'info')
         return redirect(url_for('account'))
     else:
         request.methods = 'GET'
         user = users_collection.find_one({'_id':ObjectId(user_id)})
         form.username.data = user.get('username')
         form.email.data = user.get('email')
     image_file = url_for('static',filename= 'profilePics/' + user.get('profile_picture',""))
     return render_template('account.html',
                            image_file=image_file,form=form,username=user.get('username'),email=user.get('email'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html',error=error),404
@app.route("/search")
def search_book():
    return render_template('search.html')

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _,fileext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + fileext
    picture_path = os.path.join(app.root_path,'static/profilePics/',picture_fn)
    output_size = (125,125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn


def jwt_required_custom(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        jwt_token = session.get('jwt_token')
        if jwt_token:
            try:
                # Decode the token to check its validity
                decode_token(jwt_token)
            except Exception as e:
                # Handle expired or invalid token
                session.clear()
                flash("Session expired. Please log in again.", "warning")
                return redirect(url_for('login'))
        else:
            # No token in session
            flash("Please log in to access this page.", "info")
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function


def get_logs():
    sort_order = request.args.get('sort', 'asc')
    search_query = request.args.get('search', '')
    sort_direction = ASCENDING if sort_order == 'asc' else DESCENDING

    query = {}
    if search_query:
        query = {"$text": {"$search": f'"{search_query}"'}}

    logs_cursor = logs_collection.find(query).sort('timestamp', sort_direction)
    logs = []
    for log in logs_cursor:
        log['_id'] = str(log['_id'])
        timestamp = log.get('timestamp', None)
        if timestamp:
            log['timestamp'] = timestamp.strftime('%Y-%m-%d %H:%M:%S')
        logs.append(log)

    return logs
def process_logs_for_visualization():
    # Fetch logs from MongoDB
    logs_cursor = logs_collection.find().sort('timestamp', ASCENDING)
    logs = list(logs_cursor)

    # Count logs by day
    log_count_by_day = Counter()
    for log in logs:
        date_str = log['timestamp'].strftime('%Y-%m-%d')
        log_count_by_day[date_str] += 1

    # Convert to format suitable for Chart.js
    labels = sorted(log_count_by_day)
    values = [log_count_by_day[date] for date in labels]

    return {"labels": labels, "values": values}
@app.route('/fetch_logs', methods=['GET'])
@jwt_required_custom
def fetch_logs():
    try:
        data = process_logs_for_visualization()
        logs = get_logs()
        return render_template('logs_list.html', data=data, logs=logs)
    except Exception as e:
        return str(e), 500



@app.route('/logs_visualization')
def logs_visualization():
    try:
        data = process_logs_for_visualization()
        logs = get_logs()
        return render_template('logs_visualization.html', data=data, logs=logs)
    except Exception as e:
        return str(e), 500
if __name__ == '__main__':
    app.run(debug=True)
