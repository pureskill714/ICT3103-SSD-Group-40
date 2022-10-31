# from google API part 1, must put future import at start
from __future__ import print_function  # not sure if can remove this

# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, make_response, session
from flask_sqlalchemy import SQLAlchemy  # to create db and an instance of sql Alchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, validators, SelectField, \
    DateField, TelField
from wtforms.validators import InputRequired, Length, ValidationError, Email, DataRequired, EqualTo
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, CSRFError
import pymssql
import datetime
from datetime import date, timedelta
from itsdangerous import URLSafeTimedSerializer

# import library for OTP
import math, random

import os
import base64

# for google API stuff (part 2)
import os.path
import base64
from email.message import EmailMessage

import google.auth
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
# os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "path_to_your_.json_credential_file"

# for logging with a confide to put in date and time before the message logging
import logging

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

data1 = os.urandom(16)
secret = "secretcode"
code = bytes(secret, "utf-8")
data3 = base64.b64encode(code)
seckey = data1 + data3  # Random 16bytes+base16

app = Flask(__name__, static_url_path='/static')  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = 'thisisasecretkey'  # flask uses secret to secure session cookies and protect our webform
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # To give session timeout if user idle
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdMHXAiAAAAACouP_eGKx_x6KYgrAwnPIQUIpNe'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdMHXAiAAAAAP3uAfsgPERmaMdA9ITnVIK1vn9W'
# against attacks such as Cross site request forgery (CSRF)
bcrypt = Bcrypt(app)

csrf = CSRFProtect(app)  # globally enable csrf protection within the application

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)


# function to generate OTP
def generateOTP():
    # Declare a string variable, only digits in this case
    string = '0123456789'
    sixotp = ""
    length = len(string)
    for i in range(6):
        sixotp += string[math.floor(random.random() * length)]

    return sixotp


def gmail_send_message(otp, emailadd):
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    directory = os.getcwd()
    print("this is the directory " + directory)
    x = directory + "\\token.json"
    print(x)
    print("but here can print")

    ### idk why cannot call this file
    if os.path.exists(x):
        print("IT ENTERS THE PATH BRO")
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        print(str(creds))

    # creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    # creds, _ = google.auth.default()

    try:
        service = build('gmail', 'v1', credentials=creds)
        message = EmailMessage()

        message.set_content('OTP for Cozy Room Inn is ' + otp)

        message['To'] = (emailadd)
        message['From'] = 'noreply.cozyinn@gmail.com'
        message['Subject'] = ('OTP for Cozy Room Inn is ' + otp)

        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {
            'raw': encoded_message
        }
        # pylint: disable=E1101
        send_message = (service.users().messages().send
                        (userId="me", body=create_message).execute())
        print(F'Message Id: {send_message["id"]}')
        print(send_message)
    except HttpError as error:
        print(F'An error occurred: {error}')
        send_message = None
    return send_message


# Handling the login validation for Customers
login_manager = LoginManager()  # Allow our app and flask login to work together
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = u"Username or Password incorrect. Please try again"

ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


# not sure what this does, can we remove?
@login_manager.user_loader
def load_user_customer(user_id):
    return 1


class RegisterForm(FlaskForm):
    # For users to choose a first name
    firstname = StringField('First Name', validators=[InputRequired(),
                                        Length(min=2, max=64)])
    # For users to choose a last name
    lastname = StringField('Last Name', validators=[InputRequired(),
                                       Length(min=2, max=64)])

    # For users to input their email
    email = EmailField('Email', validators=[InputRequired("Please enter email address"),
                                   Length(min=4, max=254), Email()])

    # For users to choose a username
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=32)])
    # For users to choose a password
    password = PasswordField(label='Password', validators=[InputRequired(),
                                                           validators.Length(min=8, max=64),
                                                           validators.EqualTo('password_confirm',
                                                                              message='Passwords must match,Please try again')])

    # For users to confirm password
    password_confirm = PasswordField(label='Password confirm', validators=[InputRequired(),
                                                                           validators.Length(min=8, max=32)])

    # For users to enter their contact number
    contact = IntegerField('Contact Number', validators=[InputRequired()])

    submit = SubmitField("Register")  # Register button once they are done


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=32)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(),
                                         Length(min=8, max=64)], render_kw={"placeholder": "Password"})

    # For users to enter recaptcha field
    recaptcha = RecaptchaField()

    submit = SubmitField("Login")


class MfaForm(FlaskForm):
    # For users to enter otp
    mfa = StringField(validators=[InputRequired(), Length(min=6, max=6)])


class StaffRegisterForm(FlaskForm):
    # For users to choose a first name
    firstname = StringField(validators=[InputRequired(),
                                        Length(min=2, max=64)])
    # For users to choose a last name
    lastname = StringField(validators=[InputRequired(),
                                       Length(min=2, max=64)])

    # For users to input their email
    email = EmailField(validators=[InputRequired("Please enter email address"),
                                   Length(min=4, max=254), Email()])

    # For users to choose a username
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=32)])

    # For users to enter their contact number
    contact = IntegerField(validators=[InputRequired()])

    submit = SubmitField("Register")  # Register button once they are done


class BookingForm(FlaskForm):
    room_type = SelectField(u'Room Type',
                            choices=[('Standard Twin', 'Standard Twin'), ('Standard Queen', 'Standard Queen'),
                                     ('Deluxe', 'Deluxe')])
    today = date.today()
    start_date = DateField('Start Date', format='%Y-%m-%d', default=today, validators=(validators.DataRequired(),))
    end_date = DateField('End date', validators=[DataRequired()])
    submit = SubmitField('Book')

    def validate_start_date(self, date):
        if self.start_date.data < datetime.datetime.now().date():
            raise ValidationError('You can only book for day from today.')

    def validate_end_date(self, date):
        if self.end_date.data < self.start_date.data:
            raise ValidationError('You can only select end date after start date.')

class forgotPasswordEmailForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(),
                                             Length(min=4, max=254), Email()])
    submit = SubmitField('Reset password')

class newPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, max=64)])
    password2 = PasswordField('Confirm your new Password',
                              validators=[DataRequired(), Length(min=8, max=64),
                                          EqualTo('password', message='Passwords must match')])

class ApproveBooking(FlaskForm):
    approveButton = SubmitField('Approve Booking')


# App routes help to redirect to different pages of the website
# App routes help to redirect to different pages of the website
@app.route("/", methods=['GET', 'POST'])
def home():
    #session.clear() # To ensure the session is cleared before passing
    #session.pop('username', None) # Remove session after return to home page
    resp = app.make_response(render_template('index.html'))
    resp.set_cookie('username', expires=0)  # to set expiry time of cookie to 0 after user logout
    return resp


def encode(input):
    # Function that checks if the user inputs can be encoded and decoded to and from utf-8
    # Can help to prevent buffer overflow/code injection/
    try:
        return input.encode('utf-8', 'strict').decode('utf-8', 'strict')
    except UnicodeDecodeError:
        return None


@app.route("/login", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session.clear()  # To ensure the session is cleared before passing

        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
        cursor = conn.cursor()

        # Prevent users from entering non-ascii encoded characters
        # username = form.username.data.encode(encoding="ascii", errors="ignore")
        # print(username)

        # Run encode/decode check functions
        passwordInput = encode(form.password.data)
        username = encode(form.username.data)

        # If either values are None, then the user input could not be encoded into UTF-8
        if passwordInput is None or username is None:
            flash("Please check your user inputs again.")
            return render_template('login.html', form=form)

        # Fetches original password hash of the user and compares the hash with the password provided using bcrypt
        cursor.execute('EXEC retrieve_password @username = %s', (username))
        passwordHash = cursor.fetchone()

        # Uses bcrypt to check the password hashes and calls the login_user stored procedure to check if login was successful and to update the database accordingly.
        try:
            passResult = bcrypt.check_password_hash(passwordHash[0], passwordInput)
        except:
            # Would likely occur if there was user had keyed in an invalid username
            flash("Username or Password incorrect. Please try again")
            passResult = 0

        # res = cursor.callproc('login_user', (username, int(passResult), request.remote_addr, pymssql.output(str), pymssql.output(int),))

        cursor.execute("EXEC login_user @username = %s, @login_success = %d, @IP_Address = %s",
                       (username, int(passResult), request.remote_addr))

        try:
            res = cursor.fetchone()

            user_email = res[0]
            role_ID = res[1]
            UUID = res[2]
        except:
            # Login failed, so no user email or role ID returned to res
            user_email = None
            role_ID = None
            UUID = None

        conn.commit()
        conn.close()
        if user_email is not None:  # Login was successful
            session.permanent = True
            session['username'] = username

            generated = generateOTP()
            # when session is created need declare variable here // session['generatedOTP'] = 'my_value'
            session['generated'] = generated
            print(generated)
            print(user_email)
            gmail_send_message(generated, user_email)
            # Add code her with Flask-Authorize to determine the role of the user and redirect accordingly
            return redirect(url_for('mfa'))

            # Add code her with Flask-Authorize to determine the role of the user and redirect accordingly
            if role_ID == 1:
                return redirect(url_for('customerdashboard'))
            elif role_ID == 2:
                return redirect(url_for('managerdashboard'))
            else:
                return render_template('login.html', form=form)
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('login.html', form=form)


@app.route("/mfa", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
# @login_required  # ensure is logged then, only then can access the dashboard
def mfa():
    form = MfaForm()

    # check if the user exists in the database
    if form.validate_on_submit():
        print(form.mfa.data)
        # print("MFA CHECKING")

        if form.mfa.data == session['generated']:
            # print("MFA CHECKED")
            return redirect(url_for('customerdashboard'))
        else:
            # currently unable to flash this for some reason, it flashes on login screen instead :/
            flash("MFA incorrect. Please try again")

    return render_template('mfa.html', form=form)


@app.route("/customerdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def customerdashboard():
    if "username" in session:
        username = session["username"]
        return render_template('dashboards/customerdashboard.html', username=session['username'])
    else:
        return redirect(url_for('timeout'))


@app.route("/staffdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def staffdashboard():
    return render_template('dashboards/staffdashboard.html')


@app.route("/managerdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def managerdashboard():
    return render_template('dashboards/managerdashboard.html')


@app.route("/logout", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can log out
def logout():
    logout_user()  # log the user out
    session.clear()  # Ensure session is cleared
    session.pop('username', None)  # Remove session after user has logout
    return redirect(url_for('login'))  # redirect user back to login page


@app.route("/forgetPassword", methods=['GET', 'POST'])
def forgetPassword():
    # logout_user()  # log the user out
    form = forgotPasswordEmailForm()
    if form.validate_on_submit():
        conn = pymssql.connect(server="localhost", user='sa', password='9WoH697&p2oM', database="3203")
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE Email=%s', form.email.data)
        user_email = cursor.fetchone()
        conn.close()
        flash(f'Password reset instructions sent to {form.email.data}', 'success')
        if user_email is not None:
            from util import create_message, send_message, service

            subject = "Password reset requested"

            token = ts.dumps(user_email[5], salt='recover-key')

            recover_url = url_for(
                'reset_with_token',
                token=token,
                _external=True)

            html = render_template(
                'email/recover.html',
                recover_url=recover_url)

            message = create_message('noreply.cozyinn@gmail.com',user_email[5],subject,html)
            send_message(service=service, user_id='me', message=message)
        # return redirect(url_for('forgetPassword'))

    return render_template('forgetpassword.html', form=form)


@app.route('/forgetPassword/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    try:
        email = ts.loads(token, salt="recover-key", max_age=360)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('forgetPassword'))

    form = newPasswordForm()

    if form.validate_on_submit():
        conn = pymssql.connect(server="localhost", user='sa', password='9WoH697&p2oM', database="3203")
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM Users WHERE Email=%s', email)
        user_email = cursor.fetchone()
        conn.close()

        # user.password = form.password.data
        #
        # db.session.add(user)
        # db.session.commit()
        flash("Set new password successfully")
        # flash('Set new password successfully', 'success')

        return redirect(url_for('login'))

    return render_template('resetPasswordToken.html', form=form, token=token)


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")

        # Run encode/decode check functions
        passwordInput = encode(form.password.data)
        username = encode(form.username.data)
        email = encode(form.email.data)
        fname = encode(form.firstname.data)
        lname = encode(form.lastname.data)
        # contact = form.contact.data

        # Verifies that there are no issues with encoding
        if passwordInput is None or username is None or email is None or fname is None or lname is None:
            flash("Please check your user inputs again.")
            return render_template('newRegister.html', form=form)

        hashed_password = bcrypt.generate_password_hash(passwordInput)
        cursor = conn.cursor()

        # The old procedure for registration via running the stored procedure, not sure which method is better
        # args = (str(form.username.data), hashed_password, form.email.data, form.firstname.data, form.lastname.data, pymssql.output(int),)
        # print(args)
        # res = cursor.callproc('register_customer', args)

        # Execute statement for running the stored procedure
        # Raw inputs are formatted and parameterized into a prepared statement
        cursor.execute("EXEC register_customer @username = %s, @password = %s, @email = %s, @fname = %s, @lname = %s",
                       (username, hashed_password, email, fname, lname))
        res = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        if res == 2:
            # Stored procedure was ran successfully and user successfully registered
            return redirect(url_for('registersuccess'))  # redirect to login page after register
        elif res == 1:
            # Stored procedure was ran but failed because username or email is already in use
            # Create log and send email to user
            flash("Username or Email may already be in use. Please try again. ")
        else:
            # Somehow the stored procedure did not run for whatever reason
            flash("Username or Email may already be in use. Please try again. ")

    return render_template('newRegister.html', form=form)


@app.route("/staffregister", methods=['GET', 'POST'])
def staffregister():
    form = StaffRegisterForm()
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")

        # Run encode/decode check functions
        username = encode(form.username.data)
        email = encode(form.email.data)
        fname = encode(form.firstname.data)
        lname = encode(form.lastname.data)
        # contact = encode(form.contact.data)

        if username is None or email is None or fname is None or lname is None:
            flash("Please check your user inputs again.")
            return render_template('register.html', form=form)

        cursor = conn.cursor()
        cursor.execute("EXEC register_staff @username = %s, @email = %s, @fname = %s, @lname = %s",
                       (username, email, fname, lname))
        res = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        # Generate a reset password link and send it to the email used to create the account.
        # Since the account has no valid password assigned to it, this password link must not check if the user knows the old password.

        if res == 2:
            # Stored procedure was ran successfully and user successfully registered
            return redirect(url_for('staffregistersucess'))  # redirect to login page after register
        elif res == 1:
            # Stored procedure was ran but failed because username or email is already in use
            # Create log and send email to user
            flash("Username or Email may already be in use. Please try again. ")
        else:
            # Somehow the stored procedure did not run for whatever reason
            flash("Username or Email may already be in use. Please try again. ")

    return render_template('staffregister.html', form=form)


@app.route('/customertable')
def customertable():
    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM get_customer")
    res = cursor.fetchall()

    conn.close()
    return render_template('tables/customertable.html', users=res)


@app.route('/stafftable')
def stafftable():
    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM get_staff")
    res = cursor.fetchall()

    conn.close()
    return render_template('tables/stafftable.html', users=res)


@app.route('/pendingbookingtable', methods=['GET', 'POST'])
def pendingbookingtable():
    approve = ApproveBooking()
    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()
    get_bookings = "SELECT * FROM get_pending_bookings"
    cursor.execute(get_bookings)
    bookings = list(cursor.fetchall())
    conn.close()
    return render_template('tables/pendingbookingtable.html', bookings=bookings, approve=approve)

@app.route('/bookingtable', methods=['GET', 'POST'])
def bookingtable():
    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()
    User_UUID = 'DD542958-2979-4B20-99CE-615683E7027A'
    cursor.execute("get_my_bookings  %s", User_UUID)
    bookings = cursor.fetchall()
    conn.close()
    return render_template('tables/bookingtable.html', bookings=bookings)

@app.route('/pendingbookingapprove/<string:id>', methods=['GET', 'POST'])
def pendingBookingApprove(id):
    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()
    cursor.execute("EXEC approve_bookings %s", id)
    conn.commit()
    conn.close()
    return render_template('bookings/bookingapproved.html')

@app.route('/approvedbookingtable', methods=['GET', 'POST'])
def approvedbookingtable():
    conn = pymssql.connect("DESKTOP-7GS9BE8", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM get_approved_bookings")
    bookings = cursor.fetchall()
    conn.close()
    return render_template('tables/approvedbookingtable.html', bookings=bookings)

@app.route('/staffupdatesearch', methods=['GET', 'POST'])
def staffUpdateSearch():
    return render_template('staffCRUD/staff_update_search.html')


@app.route('/staffupdatevalue', methods=['GET', 'POST'])
def staffUpdateValue():
    username = request.form['username']

    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()
    cursor.execute("EXEC user_details %s", username)
    res = list(cursor.fetchone())
    for i in range(len(res)):
        if res[i] == None:
            res[i] = ""
    print(res)
    conn.close()

    return render_template('staffCRUD/staff_update_value.html', details=res, username=username)


@app.route('/staffupdatesubmit', methods=['GET', 'POST'])
def staffUpdateSubmit():
    username = request.form['username']
    firstname = request.form['firstname']
    lastname = request.form['lastname']
    email = request.form['email']
    address = request.form['address']
    DOB = request.form['DOB']
    country = request.form['country']
    city = request.form['city']
    contact = request.form['contact']
    print(username, firstname, lastname, email, address, DOB, country, city, contact)

    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()
    cursor.execute("EXEC update_details %s, %s, %s, %s, %s, %s, %s, %s, %d",
                   (username, email, firstname, lastname, address, DOB, country, city, contact))

    conn.commit()
    conn.close()
    return render_template('staffCRUD/staff_update_sucess.html')


@app.route('/registersuccess')
@login_required  # ensure is logged then, only then can log out
def registersuccess():
    return render_template('registersucess.html')


@app.route('/staffregistersucess')
@login_required  # ensure is logged then, only then can log out
def staffregistersucess():
    return render_template('staffregistersucess.html')


@app.route('/staffdeletesearch', methods=['GET', 'POST'])
def staffDeleteSearch():
    return render_template('staffCRUD/staff_delete_search.html')


@app.route('/staffdeletesubmit', methods=['GET', 'POST'])
def staffDeleteSubmit():
    return render_template('staffCRUD/staff_update_sucess.html')


@app.route("/timeout")
def timeout():
    session.clear()  # Ensure session is cleared
    return render_template('timeout.html')


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
        conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
        cursor = conn.cursor()

        room_type = form.room_type.data
        start_date = form.start_date.data
        end_date = form.end_date.data

        if room_type == "Standard Twin":
            room_type = 1
        elif room_type == "Standard Queen":
            room_type = 2
        elif room_type == "Deluxe":
            room_type = 3
        else:
            room_type = 1

        # Send the data to database
        cursor.execute("EXEC setup_booking 1, %d, %s, %s, %s ", (room_type, "", start_date, end_date))

        res = cursor.fetchone()[0]
        conn.commit()
        conn.close()
        if res == 1:  # Booking pending approval
            return render_template('bookings/bookingsuccess.html')
        elif res == 2:
            flash("Booking failed. No rooms of this type available during date range. Or input error detected")
        else:
            flash("Booking failed. No rooms of this type available during date range. Or input error detected")

    return render_template('bookings/bookroom.html', title='Book Rooms', form=form)


@app.route("/viewreservation", methods=['GET', 'POST'])
# @login_required
def ViewReservation():
    conn = pymssql.connect("localhost", 'sa', '9WoH697&p2oM', "3203")
    cursor = conn.cursor()

    # get the booking details of current logged in user
    cursor.execute('SELECT room_ID, start_date, end_date, booking_status from Bookings where user_id = %d', 1)
    bookings_made = cursor.fetchall()

    return render_template('bookings/viewreservation.html', bookings=bookings_made)


if __name__ == '__main__':
    app.run(debug=True)
