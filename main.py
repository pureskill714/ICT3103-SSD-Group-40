# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, make_response, session
from flask_sqlalchemy import SQLAlchemy  # to create db and an instance of sql Alchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.datastructures import ImmutableDict

from forms import *
import pymssql
import re
import flask

app = Flask(__name__, static_url_path='/static')  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = 'thisisasecretkey'  # flask uses secret to secure session cookies and protect our webform
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdMHXAiAAAAACouP_eGKx_x6KYgrAwnPIQUIpNe'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdMHXAiAAAAAP3uAfsgPERmaMdA9ITnVIK1vn9W'
# against attacks such as Cross site request forgery (CSRF)
bcrypt = Bcrypt(app)

csrf = CSRFProtect(app)  # globally enable csrf protection within the application

jinja_options = ImmutableDict(
    extensions=[
        'jinja2.ext.autoescape', 'jinja2.ext.with_'
    ])
# Turn auto escaping on
app.jinja_env.autoescape = True

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

response = flask.Response()
# We can set secure cookies in response
response.set_cookie('key', 'value', secure=True, httponly=True, samesite='Lax')

# Handling the login validation for Customers
login_manager = LoginManager()  # Allow our app and flask login to work together
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = u"Username or Password incorrect. Please try again"


# not sure what this does, can we remove?
@login_manager.user_loader
def load_user_customer(user_id):
    return 1


# App routes help to redirect to different pages of the website
@app.route("/", methods=['GET', 'POST'])
def home():
    return render_template('index.html')


@app.route("/login", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def login():
    form = LoginForm()
    # check if the user exists in the database
    if form.validate_on_submit():
        print(form.username.data)
        session['username'] = form.username.data
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-FDNFHQ1", 'sa', 'raheem600', "3103 Hotel")
        cursor = conn.cursor()

        # get the User_ID of the user who logged in
        cursor.execute('SELECT User_ID from Users where Username = %s', form.username.data)
        for row in cursor:
            data = row

        # store the userid in a session
        for userid in data:
            session['userid'] = userid
        # Fetches original password hash of the user
        # Might replace this execute command with a function for higher security
        cursor.execute('SELECT Password FROM Users WHERE Username = %s', form.username.data)

        # Uses bcrypt to check the password hashes and calls the login_user stored procedure to
        res = cursor.callproc('login_user', (
            form.username.data, (int(bcrypt.check_password_hash(cursor.fetchone()[0], form.password.data))),
            request.remote_addr, pymssql.output(str), pymssql.output(int)))

        conn.commit()
        conn.close()

        user_email = res[3]  # used for MFA function
        role_ID = res[4]  # used for Flask-Authorize to properly authorize users

        if user_email is not None:  # Login was successful
            # Add code her with Flask-Authorize to determine the role of the user and redirect accordingly
            return redirect(url_for('customerdashboard'))
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('login.html', form=form)


@app.route("/customerdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def customerdashboard():
    return render_template('dashboards/customerdashboard.html', username=session['username'])


@app.route("/staffdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def staffdashboard():
    return render_template('dashboards/staffdashboard.html')


@app.route("/managerdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def managerdashboard():
    return render_template('dashboards/managerdashboard.html')


@app.route("/logout", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can log out
def logout():
    logout_user()  # log the user out
    return redirect(url_for('login'))  # redirect user back to login page


@app.route("/forgetPassword", methods=['GET', 'POST'])
def forgetPassword():
    logout_user()  # log the user out
    return render_template('forgetpassword.html')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate():
        pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        if re.search(pattern, form.password.data):
            pass
        else:
            flash("password is not strong enough. Please try again!")
            return render_template('register.html', form=form)

    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-FDNFHQ1", 'sa', 'raheem600', "3103 Hotel")

        cursor = conn.cursor()

        # Procedure for registration
        res = cursor.callproc('register_customer', (
            form.username.data, hashed_password, form.email.data, form.firstname.data, form.lastname.data,
            pymssql.output(int),))

        conn.commit()
        conn.close()

        if res[5] == 2:
            # Stored procedure was ran successfully and 
            return redirect(url_for('registersuccess'))  # redirect to login page after register
        elif res[5] == 1:
            # Stored procedure was ran but failed because username or email is already in use
            flash("Username or Email may already be in use. Please try again. ")
        else:
            # Somehow the stored procedure did not run for whatever reason
            flash("Username or Email may already be in use. Please try again. ")

    return render_template('register.html', form=form)


@app.route('/customertable')
@login_required  # ensure is logged then, only then can log out
def customertable():
    # Implement authorization with Flask-Authorize
    return render_template('tables/customertable.html')


@app.route('/stafftable')
@login_required  # ensure is logged then, only then can log out
def stafftable():
    # Implement authorization with Flask-Authorize
    return render_template('tables/stafftable.html')


@app.route('/registersuccess')
def registersuccess():
    return render_template('registersucess.html')


# 400 - To handle Bad request
@app.route('/400')
def error400():
    abort(400)


# 401 - To handle error of Unauthorized request
@app.route('/401')
def error401():
    abort(401)


# 404 - To handle error in matching the Request URL
@app.route('/404')
def error404():
    abort(404)


# 500 - To handle error in Internal Server Error
@app.route('/500')
def error500():
    abort(500)


# To direct to 400 page
@app.errorhandler(400)
def unauthorized_page(error):
    return render_template('400.html'), 400


# To direct to 401 page
@app.errorhandler(401)
def unauthorized_page(error):
    return render_template('401.html'), 401


# To direct to 404 page
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


# To direct to 500 page
@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


# To direct to CSRF validation error
@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    return render_template('403.html'), 403


@app.route("/booking", methods=['GET', 'POST'])
# @login_required
def booking():
    form = BookingForm()
    if form.validate_on_submit():
        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-FDNFHQ1", 'sa', 'raheem600', "3103 Hotel")
        cursor = conn.cursor()

        data = ()
        cursor.execute('SELECT room_type,start_date,end_date from Bookings2 where user_id = %d', session['userid'])
        for row in cursor:
            data = row

        # User has booked a room prior, do not allow additional booking unless cancelled first
        if len(data) != 0:
            flash(
                "A reservation by this account has already been found in the system. Please make another booking after your check-out day.")
            return render_template('bookings/bookroom.html', title='Book Rooms', form=form)

        insert_stmt = (
            "INSERT INTO Bookings2 (user_id,room_type, start_date, end_date)"
            "VALUES (%d,%s, %s, %s)"
        )
        data = (session["userid"], form.room_type.data, form.start_date.data, form.end_date.data)

        # Send the data to database
        cursor.execute(insert_stmt, data)

        conn.commit()
        conn.close()
        return render_template('bookings/bookingsuccess.html')

    return render_template('bookings/bookroom.html', title='Book Rooms', form=form)


@app.route("/reservation", methods=['GET', 'POST'])
# @login_required
def reservation():
    conn = pymssql.connect("DESKTOP-FDNFHQ1", 'sa', 'raheem600', "3103 Hotel")
    cursor = conn.cursor()

    # get the booking details of current logged in user
    data = ()
    cursor.execute('SELECT room_type,start_date,end_date from Bookings2 where user_id = %d', session['userid'])
    for row in cursor:
        data = row

    if len(data) != 0:
        room_type = data[0]
        start_date = data[1]
        end_date = data[2]
    else:
        return render_template('bookings/noreservation.html')

    return render_template('bookings/reservation.html', room_type=room_type, start_date=start_date, end_date=end_date)


@app.route("/cancelbooking", methods=['GET', 'POST'])
def cancelbooking():
    cancel = CancelReservation()
    conn = pymssql.connect("DESKTOP-FDNFHQ1", 'sa', 'raheem600', "3103 Hotel")
    cursor = conn.cursor()

    # get the booking details of current logged in user
    data = ()
    cursor.execute('SELECT room_type,start_date,end_date from Bookings2 where user_id = %d', session['userid'])
    for row in cursor:
        data = row

    if len(data) != 0:
        room_type = data[0]
        start_date = data[1]
        end_date = data[2]
    else:
        return render_template('bookings/noreservation.html')

    # when user press the cancel booking button
    if request.method == 'POST':
        cursor.execute('DELETE FROM Bookings2 WHERE user_id = %d', session['userid'])
        conn.commit()
        conn.close()
        return render_template('bookings/cancelbookingsuccess.html')

    return render_template('bookings/cancelbooking.html', room_type=room_type, start_date=start_date, end_date=end_date,
                           cancel=cancel)


if __name__ == '__main__':
    app.run(debug=True)
