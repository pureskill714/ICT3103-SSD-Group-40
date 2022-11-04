# from google API part 1, must put future import at start
from __future__ import print_function  # not sure if can remove this

import base64
import datetime
import math
import os
# for google API stuff (part 2)
import os.path
import random
import re
from datetime import date, timedelta
from email.message import EmailMessage

import pymssql
# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, logout_user
from flask_wtf import FlaskForm, RecaptchaField, Recaptcha
from flask_wtf.csrf import CSRFProtect, CSRFError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from itsdangerous import URLSafeTimedSerializer
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, validators, SelectField, \
    DateField, HiddenField
from wtforms.validators import InputRequired, Length, ValidationError, Email, DataRequired, EqualTo

from util import cleanhtml, password_policy_check

# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
# import library for OTP

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
# os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "path_to_your_.json_credential_file"

# for logging with a confide to put in date and time before the message logging
import logging

import pyotp

import stripe

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

import pytz
import socket
from requests import get

from gapi import create_message, send_message, service

data1 = os.urandom(16)
secret = "secretcode"
code = bytes(secret, "utf-8")
data3 = base64.b64encode(code)
seckey = data1 + data3  # Random 16bytes+base64

app = Flask(__name__, static_url_path='/static')  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = seckey  # flask uses secret to secure session cookies and protect our webform
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # To give session timeout if user idle
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdMHXAiAAAAACouP_eGKx_x6KYgrAwnPIQUIpNe'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdMHXAiAAAAAP3uAfsgPERmaMdA9ITnVIK1vn9W'
# against attacks such as Cross site request forgery (CSRF)
bcrypt = Bcrypt(app)

stripe_keys = {
    'secret_key': "sk_test_51LyqY9EsefqfyEMpEdDt2yqYyWnOdWuVrKXaz81Z6pviQZGp6fOepWIO2iqkloxuKnHyXCkEMEEytaeUiZRiBCMO00obWmTQlE",
    'publishable_key': "pk_test_51LyqY9EsefqfyEMpZFIUI5eydUQKyZpNqyays3S463Hz4TEHrXCN7Yyk0dlgB7M2pkjnF1NtsdHSwWfaCmCeZvCY00yk4perh9"
}

stripe.api_key = stripe_keys['secret_key']

csrf = CSRFProtect(app)  # globally enable csrf protection within the application

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_DOMAIN=False
)


def gmail_send_message(otp, emailadd):
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    directory = os.getcwd()
    x = directory + "\\token.json"

    ### idk why cannot call this file
    if os.path.exists(x):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

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

        message.set_content(
            'OTP for Cozy Room Inn is ' + otp + '\n\nIf you did not attempt a login to your account, please contact an administrator immediately')

        message['To'] = (emailadd)
        message['From'] = 'noreply.cozyinn@gmail.com'
        message['Subject'] = ('Login attempt to Cozy Room Inn')

        # encoded message
        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

        create_message = {
            'raw': encoded_message
        }
        # pylint: disable=E1101
        send_message = (service.users().messages().send
                        (userId="me", body=create_message).execute())
        
        # print(F'Message Id: {send_message["id"]}')
    except HttpError as error:

        # print(F'An error occurred: {error}')
        send_message = None
    return send_message



def encode(input):
    # Function that checks if the user inputs can be encoded and decoded to and from utf-8
    # Can help to prevent buffer overflow/code injection/
    try:
        return input.encode('utf-8', 'strict').decode('utf-8', 'strict')
    except UnicodeDecodeError:
        return None


# Handling the login validation for Customers
login_manager = LoginManager()  # Allow our app and flask login to work together
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = u"Username or Password incorrect. Please try again"

ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])


@login_manager.user_loader
def load_user_customer(user_id):
    return 1


def check_session(username, session_ID):
    username = encode(username)
    session_ID = session_ID
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute('EXEC check_session %s, %s', (username, session_ID))

    res = cursor.fetchone()
    conn.close()

    if res is not None:
        return res
    else:
        logout_user()  # log the user out
        session.clear()  # Ensure session is cleared
        session.pop('username', None)  # Remove session after user has logout
    return None


def delete_session(username, session_ID):
    username = encode(username)
    session_ID = session_ID
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute('EXEC delete_session %s, %s', (username, session_ID))
    conn.commit()
    conn.close()

    return None


class RegisterForm(FlaskForm):
    # For users to choose a first name
    firstname = StringField('First Name', validators=[InputRequired(),
                                                      Length(min=2, max=64)])
    # For users to choose a last nameaddress
    lastname = StringField('Last Name', validators=[InputRequired(),
                                                    Length(min=2, max=64)])

    # For users to input their email
    email = EmailField('Email', validators=[InputRequired("Please enter email address"),
                                            Length(min=4, max=254), Email(granular_message=True, check_deliverability=True)])

    # For users to choose a username
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=32)])
    # For users to choose a password
    password = PasswordField(label='Password', validators=[InputRequired(), password_policy_check,
                                                           validators.Length(min=8, max=64)])

    # For users to confirm password
    password_confirm = PasswordField(label='Password confirm', validators=[InputRequired(),
                                                                           validators.EqualTo('password',
                                                                                              message='Passwords must match, Please try again')])

    # For users to enter their contact number
    contact = IntegerField('Contact Number', validators=[InputRequired()])

    recaptcha = RecaptchaField()

    submit = SubmitField("Register")  # Register button once they are done


class EditProfileForm(FlaskForm):
    # For users to choose a first name
    firstname = StringField('First Name', validators=[InputRequired(),
                                                      Length(min=2, max=64)])
    # For users to choose a last nameaddress
    lastname = StringField('Last Name', validators=[InputRequired(),
                                                    Length(min=2, max=64)])

    # For users to input their email
    email = EmailField('Email', validators=[InputRequired("Please enter email address"),
                                            Length(min=4, max=254), Email(check_deliverability=True)])

    # For users to choose a username
    username = StringField(render_kw={'disabled': True})
    country = StringField(validators=[Length(max=128)])
    city = StringField(validators=[Length(max=128)])
    address = StringField(validators=[Length(max=255)])
    dob = DateField("Date of Brith", validators=[validators.Optional()])

    # For users to choose a password
    password = PasswordField(label='Current Password', validators=[InputRequired(),
                                                                   validators.Length(min=8, max=64)])

    # For users to enter their contact number
    contact = IntegerField('Contact Number', validators=[InputRequired()])

    recaptcha = RecaptchaField()

    submit = SubmitField("Save changes")  # Register button once they are done


class ChangePasswordForm(FlaskForm):
    # For users to choose a password
    password = PasswordField(label='Current Password', validators=[InputRequired(),
                                                                   validators.Length(min=8, max=64)])

    # For users to confirm password
    password2 = PasswordField(label='New Password', validators=[InputRequired(),
                                                                validators.Length(min=8, max=64),
                                                                validators.EqualTo('password_confirm2',
                                                                                   message='Passwords must match, Please try again')])
    # For users to confirm password
    password_confirm2 = PasswordField(label='Confirm New Password', validators=[InputRequired(),
                                                                                validators.Length(min=8, max=64),
                                                                                validators.EqualTo('password2',
                                                                                                   message='Passwords must match, Please try again')])
    submitp = SubmitField("Save")  # Register button once they are done


class EditProfileForm(FlaskForm):
    # For users to choose a first name
    firstname = StringField('First Name', validators=[InputRequired(),
                                                      Length(min=2, max=64)])
    # For users to choose a last nameaddress
    lastname = StringField('Last Name', validators=[InputRequired(),
                                                    Length(min=2, max=64)])

    # For users to input their email
    email = EmailField('Email', validators=[InputRequired("Please enter email address"),
                                            Length(min=4, max=254), Email(check_deliverability=True)])

    # For users to choose a username
    username = StringField(render_kw={'disabled': True})
    country = StringField(validators=[Length(max=128)])
    city = StringField(validators=[Length(max=128)])
    address = StringField(validators=[Length(max=255)])
    dob = DateField("Date of Brith", validators=[validators.Optional()])

    # For users to choose a password
    password = PasswordField(label='Current Password', validators=[InputRequired(),
                                                                   validators.Length(min=8, max=64)])

    # For users to enter their contact number
    contact = IntegerField('Contact Number', validators=[InputRequired()])

    recaptcha = RecaptchaField()

    submit = SubmitField("Save changes")  # Register button once they are done


class ChangePasswordForm(FlaskForm): # THIS SHOULD BE DELETED, DUPLICATE CODE
    # For users to choose a password
    password = PasswordField(label='Current Password', validators=[InputRequired(),
                                                                   validators.Length(min=8, max=64)])

    # For users to confirm password
    password2 = PasswordField(label='New Password', validators=[InputRequired(),
                                                                validators.Length(min=8, max=64),
                                                                password_policy_check])
    # For users to confirm password
    password_confirm2 = PasswordField(label='Confirm New Password', validators=[InputRequired(),
                                                                                validators.Length(min=8, max=64),
                                                                                validators.EqualTo('password2',
                                                                                                   message='Passwords must match, Please try again')])
    submitp = SubmitField("Save")  # Register button once they are done


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=32)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(),
                                         Length(min=8, max=64)], render_kw={"placeholder": "Password"})

    # For users to enter recaptcha field
    recaptcha = RecaptchaField(validators=[Recaptcha(message="Please complete captcha")])

    submit = SubmitField("Login")


class MfaForm(FlaskForm):
    # For users to enter otp
    mfa = HiddenField(validators=[InputRequired()])


class VerifyEmailForm(FlaskForm):
    # For users to input their email
    email = EmailField('Email', validators=[InputRequired("Please enter email address"),
                                            Length(min=4, max=254), Email(check_deliverability=True)])
    recaptcha = RecaptchaField()

    submit = SubmitField("Send Verification Link")  # Register button once they are done


###### Manager's CRUD staff's data ######
# 1) Register staff  
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

    recaptcha = RecaptchaField()

    submit = SubmitField("Register")  # Register button once they are done


# 2) Create staff account
class createStaffAccount(FlaskForm):
    # For users to choose a first name
    firstname = StringField(validators=[InputRequired(),
                                        Length(min=2, max=64)])
    # For users to choose a last name
    lastname = StringField(validators=[InputRequired(),
                                       Length(min=2, max=64)])
    # For users to input their email
    email = EmailField(validators=[InputRequired("Please enter email address"),
                                   Length(min=4, max=254), Email()])

    recaptcha = RecaptchaField()

    submit = SubmitField('Create Staff')


# 3) Update staff account
class updateStaffAccount(FlaskForm):
    # For users to choose a first name
    firstname = StringField(validators=[InputRequired(),
                                        Length(min=2, max=64)])
    # For users to choose a last name
    lastname = StringField(validators=[InputRequired(),
                                       Length(min=2, max=64)])
    # For users to input their email
    email = EmailField(validators=[InputRequired("Please enter email address"),
                                   Length(min=4, max=254), Email()])

    submit = SubmitField('Update')


# 4) Delete staff account


class deleteStaffAccount(FlaskForm):

    recaptcha = RecaptchaField()  

    deleteButton = SubmitField('Delete staff')


###### Staff RUD
###### Customer CRUD   
# 1) Create, register and update Booking data
class BookingForm(FlaskForm):
    room_type = SelectField(u'Room Type',
                            choices=[('Standard Twin', 'Standard Twin'), ('Standard Queen', 'Standard Queen'),
                                     ('Deluxe', 'Deluxe')])
    today = date.today()
    start_date = DateField('Start Date', format='%Y-%m-%d', default=today, validators=(validators.DataRequired(),))
    end_date = DateField('End date', validators=[DataRequired()])
    submit = SubmitField('Book Now')

    def validate_start_date(self, date):
        if self.start_date.data < datetime.datetime.now().date():
            raise ValidationError('You can only book for day from today.')

    def validate_end_date(self, date):
        if self.end_date.data < self.start_date.data:
            raise ValidationError('You can only select end date after start date.')


class deleteBooking(FlaskForm):
    deleteButton = SubmitField('Delete')


class forgotPasswordEmailForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(),
                                            Length(min=4, max=254), Email()])

    recaptcha = RecaptchaField()

    submit = SubmitField('Reset password')


class newPasswordForm(FlaskForm):
    password = PasswordField('New Password',

                             validators=[DataRequired(), Length(min=8, max=64),
                                         password_policy_check])
    password2 = PasswordField('Confirm your new Password',
                              validators=[DataRequired(), Length(min=8, max=64),
                                          EqualTo('password', message='Passwords must match')])


class ApproveBooking(FlaskForm):
    approveButton = SubmitField('Approve')


class StaffSearchForm(FlaskForm):
    username = StringField("Employee Username", validators=[InputRequired(),
                                                            Length(min=4, max=32)])
    submit = SubmitField('Submit')


class StaffUpdateForm(FlaskForm):
    # For users to choose a first name
    firstname = StringField('First Name', validators=[InputRequired(),
                                                      Length(min=2, max=64)])
    # For users to choose a last nameaddress
    lastname = StringField('Last Name', validators=[InputRequired(),
                                                    Length(min=2, max=64)])

    # For users to input their email
    email = EmailField('Email', validators=[InputRequired("Please enter email address"),
                                            Length(min=4, max=254),
                                            Email(granular_message=True, check_deliverability=True)])

    # For users to choose a username
    username = StringField(render_kw={'readonly': True})
    country = StringField(validators=[Length(max=128)])
    city = StringField(validators=[Length(max=128)])
    address = StringField(validators=[Length(max=255)])
    dob = DateField("Date of Brith", validators=[validators.Optional()])

    # For users to enter their contact number
    contact = IntegerField('Contact Number', validators=[InputRequired()])

    recaptcha = RecaptchaField()

    submit = SubmitField("Save changes")  # Register button once they are done


# App routes help to redirect to different pages of the website
@app.route("/", methods=['GET', 'POST'])
def home():
    try:
        res = check_session(session['username'], session['Session_ID'])
    except:
        # User is not logged in
        res = '00'
    if (res[1] == 'Customer'):
        return redirect(url_for('customerdashboard'))
    elif (res[1] == 'Staff'):
        return redirect(url_for('staffdashboard'))
    elif (res[1] == 'Manager'):
        return redirect(url_for('managerdashboard'))
    else:
        resp = app.make_response(render_template('index.html'))
        # resp.set_cookie('username', expires=0)  # to set expiry time of cookie to 0 after user logout
        return resp


@app.route("/login", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def login():
    form = LoginForm()
    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    if form.validate_on_submit():
        session.clear()  # To ensure the session is cleared before passing

        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()

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
            cursor.execute("EXEC login_user @username = %s, @login_success = %d, @IP_Address = %s",
                           (username, int(passResult), encode(get('https://api.ipify.org').text)))

            try:
                res = cursor.fetchone()
                global UUID
                ####verified_status=res[x]
                user_email = res[0]
                UUID = res[1]
            except:
                # Login failed, so no user email or role ID returned to res
                user_email = None
                UUID = None

            conn.commit()
            conn.close()
            if user_email is not None:  # Login was successful, now need to check verified_status

                #### if verified_status = 'true':
                
                session['username'] = username

                otpsecret = base64.b32encode(os.urandom(10)).decode('utf-8')
                session['secret'] = otpsecret
                totp = pyotp.TOTP(otpsecret)

                gmail_send_message(totp.now(), user_email)
                # Add code her with Flask-Authorize to determine the role of the user and redirect accordingly
                return redirect(url_for('mfa'))

                #### else:
                #### return redirect(url_for('request verification'))

            else:
                conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
                cursor = conn.cursor()
                insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
                data = (time_date_aware, "auth_login_failed", "Warn", hostname, source_ip, destination_ip, browser,
                        f"User login attempt failed")

                cursor.execute(insert_stmt, data)
                conn.commit()
                conn.close()
                flash("Username or Password incorrect. Please try again")
                return redirect(url_for('login'))
        except:
            # Would likely occur if there was user had keyed in an invalid username
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (time_date_aware, "auth_login_failed", "Warn", hostname, source_ip, destination_ip, browser,
                    f"User login attempt failed")

            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()

            flash("Username or Password incorrect. Please try again")
            return redirect(url_for('login'))
            passResult = 0

    return render_template('login.html', form=form)


@app.route("/mfa", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
# @login_required  # ensure is logged then, only then can access the dashboard
def mfa():
    form = MfaForm()
    totp = pyotp.TOTP(session['secret'])
    # check if the user exists in the database
    if form.validate_on_submit():
        # Valid window extends the validity to this many counter ticks before and after the current one
        # Counter ticks are generally a few miliseconds long
        if totp.verify(form.mfa.data, valid_window=1):
            session['User_ID'] = UUID
            Session_ID = os.urandom(16)
            session['Session_ID'] = Session_ID

            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()

            cursor.execute('EXEC create_session %s, %s', (session['username'], Session_ID))
            session_check = cursor.fetchone()
            conn.commit()
            conn.close()

            hostname = encode(socket.gethostname())
            source_ip = encode(get('https://api.ipify.org').text)
            destination_ip = encode(request.remote_addr)
            browser = str(request.user_agent)
            time_date_aware = datetime.datetime.now(pytz.utc)

            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (time_date_aware, "aunth_login_success", "Info", hostname, source_ip, destination_ip, browser,
                    f"User {session['User_ID']} login successfully")
            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()

            res = check_session(session['username'], session['Session_ID'])
            print(res)
            if (res[1] == 'Customer'):
                return redirect(url_for('customerdashboard'))
            elif (res[1] == 'Staff'):
                return redirect(url_for('staffdashboard'))
            elif (res[1] == 'Manager'):
                return redirect(url_for('managerdashboard'))
            else:
                return render_template('403.html'), 403

        else:
            # currently unable to flash this for some reason, it flashes on login screen instead :/
            flash("MFA incorrect. Please try again", "danger")

    return render_template('mfa.html', form=form)


@app.route("/customerdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def customerdashboard():
    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Customer'):
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
        data = (time_date_aware, "authorization_failed", "Critical", hostname, source_ip, destination_ip, browser,
                f"An attempt to access the staff dashboard without entitlement was made")
        cursor.execute(insert_stmt, data)
        conn.commit()
        conn.close()
        return render_template('403.html'), 403

    if "username" in session:
        username = session["username"]
        return render_template('dashboards/customerdashboard.html', username=session['username'])
    else:
        return redirect(url_for('timeout'))


@app.route("/staffdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def staffdashboard():
    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Staff'):
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
        data = (time_date_aware, "authorization_failed", "Critical", hostname, source_ip, destination_ip, browser,
                f"An attempt to access the staff dashboard without entitlement was made")
        cursor.execute(insert_stmt, data)
        conn.commit()
        conn.close()
        return render_template('403.html'), 403
    return render_template('dashboards/staffdashboard.html')


@app.route("/managerdashboard", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can access the dashboard
def managerdashboard():
    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Manager'):
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
        data = (time_date_aware, "authorization_failed", "Critical", hostname, source_ip, destination_ip, browser,
                f"An attempt to access the manager dashboard without entitlement was made")
        cursor.execute(insert_stmt, data)
        conn.commit()
        conn.close()
        return render_template('403.html'), 403
    return render_template('dashboards/managerdashboard.html')


@app.route("/logout", methods=['GET', 'POST'])
# @login_required  # ensure is logged then, only then can log out
def logout():
    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    res = check_session(session['username'], session['Session_ID'])
    if not (res[1] == 'Customer' or res[1] == 'Staff' or res[1] == 'Manager'):
        return render_template('403.html'), 403

    try:
        check_session(session['username'], session['Session_ID'])
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
        data = (time_date_aware, "aunth_logout_success", "Info", hostname, source_ip, destination_ip, browser,
                f"User {session['User_ID']} logout successfully")
        cursor.execute(insert_stmt, data)
        conn.commit()
        conn.close()
        delete_session(session['username'], session['Session_ID'])
    except:
        return render_template('403.html'), 403
    logout_user()  # log the user out
    session.clear()  # Ensure session is cleared
    session.pop('username', None)  # Remove session after user has logout

    return redirect(url_for('login'))  # redirect user back to login page


@app.route("/forgetPassword", methods=['GET', 'POST'])
def forgetPassword():
    logout_user()  # log the user out
    form = forgotPasswordEmailForm()

    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    if form.validate_on_submit():
        email = encode(form.email.data)
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        cursor.execute('EXEC check_email %s', form.email.data)
        result = cursor.fetchone()
        conn.close()
        flash(f'If that email address exists, we will send you an email to reset your password.', 'success')

        if (result[0] == 1):
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (
                time_date_aware, "forget_password_email_successful_sent", "Info", hostname, source_ip, destination_ip,
                browser,
                f"Password reset link successfully sent to email {email}")
            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()
            # Email of the user found

            subject = "Password reset requested"
            global salt
            salt = os.urandom(32)
            token = ts.dumps(email, salt)

            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            cursor.execute('EXEC update_token_reset %s, %s', (email, token))
            conn.commit()
            conn.close()

            recover_url = url_for(
                'reset_with_token',
                token=token,
                _external=True)

            html = render_template(
                'email/recover.html',
                recover_url=recover_url)

            message = create_message('noreply.cozyinn@gmail.com', email, subject, html)
            send_message(service=service, user_id='me', message=message)

        elif (result[0] == 2):
            # email of the user not found, create log with IP here
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (
                time_date_aware, "forget_password_email_failed_sent", "Warn", hostname, source_ip, destination_ip,
                browser,
                f"Password reset link failed to sent to email {email}")
            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()
            ip_addr = request.remote_addr

    return render_template('forgetpassword.html', form=form)

@app.route("/requestVerification", methods=['GET', 'POST'])
def requestVerification():
    logout_user()  # log the user out
    form = VerifyEmailForm()

    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    if form.validate_on_submit():
        email = encode(form.email.data)
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        cursor.execute('EXEC check_email %s', form.email.data)
        result = cursor.fetchone()
        conn.close()
        flash(f'If that email address exists, we will send you a verification link.', 'success')

        if (result[0] == 1):
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (
                time_date_aware, "verification_link_successfuly_sent", "Info", hostname, source_ip, destination_ip,
                browser,
                f"Verification link successfully sent to email {email}")
            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()
            # Email of the user found

            subject = "Click link to verify account on Cozy Room Inn here."
            global salt
            salt = os.urandom(32)
            token = ts.dumps(email, salt)

            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            cursor.execute('EXEC update_token_reset %s, %s', (email, token))
            conn.commit()
            conn.close()

            verify_url = url_for(
                'verify_with_token',
                token=token,
                _external=True)

            html = render_template(
                'email/verify.html',
                verify_url=verify_url)

            message = create_message('noreply.cozyinn@gmail.com', email, subject, html)
            send_message(service=service, user_id='me', message=message)

        elif (result[0] == 2):
            # email of the user not found, create log with IP here
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (
                time_date_aware, "verification_email_failed_sent", "Warn", hostname, source_ip, destination_ip,
                browser,
                f"Verification link failed to sent to {email}")
            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()
            ip_addr = request.remote_addr

    return render_template('requestverification.html', form=form)


@app.route('/forgetPassword/<token>', methods=["GET", "POST"])
def reset_with_token(token):
    try:
        email = ts.loads(token, salt=salt, max_age=360)
        # check database for token
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        cursor.execute('EXEC retrieve_token_reset @Email = %s', email)
        token_check = cursor.fetchone()
        conn.commit()
        conn.close()
        print(email)
        if token_check[0] != token:
            raise Exception("no match")
    except:
        # print(e)
        form = forgotPasswordEmailForm()
        flash('The confirmation link is invalid or has expired.', 'danger')
        return render_template('forgetpassword.html', form=form)
    
    # After successfully checking the token, allow the user to key in new password
    form = newPasswordForm()   

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        #### we can add a check password to ensure old password isn't used, code below may not be right yet
        # Fetches original password hash of the user based on email and compares the hash with the password provided using bcrypt
        # cursor.execute('EXEC retrieve_password @email = %s', (email))
        # passwordHash = cursor.fetchone()

        # passResult = bcrypt.check_password_hash(passwordHash[0], hashed_password)
        # cursor.execute("EXEC login_user @email = %s, @login_success = %d, @IP_Address = %s",
        #                    (email, int(passResult), encode(get('https://api.ipify.org').text)))

        cursor.execute('EXEC update_password %s, %s', (email, hashed_password))
        conn.commit()
        cursor.execute('EXEC update_token_reset %s, %s', (email, ""))
        conn.commit()
        conn.close()


        tz = pytz.timezone('Asia/Singapore')
        subject = "Your password was changed"
        html = render_template(
            'email/passwordresetnotification.html',
            time=datetime.datetime.now(tz),
            IPaddr=encode(get('https://api.ipify.org').text),
            browser=str(request.user_agent.string))
        message = create_message('noreply.cozyinn@gmail.com', email, subject, html)
        send_message(service=service, user_id='me', message=message)
        flash("Set new password successfully", 'success')
        return redirect(url_for('login'))

    return render_template('resetPasswordToken.html', form=form, token=token)

@app.route('/requestVerification/<token>', methods=["GET", "POST"])
def verify_with_token(token):
    try:
        email = ts.loads(token, salt=salt, max_age=360)
        # check database for token
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        cursor.execute('EXEC retrieve_token_reset @Email = %s', email)
        token_check = cursor.fetchone()
        conn.commit()
        conn.close()
        # print(email)
        if token_check[0] != token:
            raise Exception("no match")
        else:
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            # cursor.execute('EXEC update_verification_status %s, %s', (email, "true? or 1"))
            conn.commit()
            # reset token
            cursor.execute('EXEC update_token_reset %s, %s', (email, ""))
            conn.commit()
            conn.close()

            tz = pytz.timezone('Asia/Singapore')
            subject = "Your Cozy Room Inn account has been verified!"
            html = render_template(
                'email/verifiedaccountnotification.html',
                time=datetime.datetime.now(tz),
                IPaddr=encode(get('https://api.ipify.org').text),
                browser=str(request.user_agent.string))
            message = create_message('noreply.cozyinn@gmail.com', email, subject, html)
            send_message(service=service, user_id='me', message=message)
            flash("Your account is successfully verified!", 'success')
            return redirect(url_for('registersucess'))
    except:
        # print('expired')
        form = VerifyEmailForm()
        flash('The verification link is invalid or has expired.', 'danger')
        return render_template('requestVerification.html', form=form)  


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")

        # Run encode/decode check functions
        passwordInput = encode(form.password.data)
        username = encode(form.username.data)
        email = encode(form.email.data)
        fname = encode(form.firstname.data)
        lname = encode(form.lastname.data)
        contact = form.contact.data

        # Verifies that there are no issues with encoding
        if passwordInput is None or username is None or email is None or fname is None or lname is None:
            flash("Please check your user inputs again.")
            return render_template('register.html', form=form)

        hashed_password = bcrypt.generate_password_hash(passwordInput)
        cursor = conn.cursor()

        # Execute statement for running the stored procedure
        # Raw inputs are formatted and parameterized into a prepared statement
        cursor.execute(
            "EXEC register_customer @username = %s, @password = %s, @email = %s, @fname = %s, @lname = %s, @contact = %s",
            (username, hashed_password, email, fname, lname, contact))
        res = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        if res == 2:
            # Stored procedure was ran successfully and user successfully registered
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (
                time_date_aware, "aunth_create_user_role_id_1", "Warn", hostname, source_ip, destination_ip, browser,
                f"User {username}(role id 1:Customer) created successfully")
            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()
            
            subject = "Click link to verify account on Cozy Room Inn here."
            global salt
            salt = os.urandom(32)
            token = ts.dumps(email, salt)

            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            cursor.execute('EXEC update_token_reset %s, %s', (email, token))
            conn.commit()
            conn.close()

            verify_url = url_for(
                'verify_with_token',
                token=token,
                _external=True)

            html = render_template(
                'email/verify.html',
                verify_url=verify_url)

            message = create_message('noreply.cozyinn@gmail.com', email, subject, html)
            send_message(service=service, user_id='me', message=message)
            return redirect(url_for('registersuccess'))  # redirect to login page after register
        elif res == 1:
            conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
            cursor = conn.cursor()
            insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
            data = (
                time_date_aware, "input_validation_fail", "Warn", hostname, source_ip, destination_ip, browser,
                f"Attempt to create new customer account with existing Username : {username} or email : {email}")
            cursor.execute(insert_stmt, data)
            conn.commit()
            conn.close()

            # Stored procedure was ran but failed because username or email is already in use
            # Create log and send email to user
            flash("Username or Email may already be in use. Please try again. ")
        else:
            # Somehow the stored procedure did not run for whatever reason
            flash("Username or Email may already be in use. Please try again. ")

    return render_template('register.html', form=form)


@app.route("/staffregister", methods=['GET', 'POST'])
def staffregister():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Manager'):
        return render_template('403.html'), 403
    form = StaffRegisterForm()
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")

        # Run encode/decode check functions
        username = encode(form.username.data)
        email = encode(form.email.data)
        fname = encode(form.firstname.data)
        lname = encode(form.lastname.data)
        contact = form.contact.data

        if username is None or email is None or fname is None or lname is None:
            flash("Please check your user inputs again.")
            return render_template('register.html', form=form)

        cursor = conn.cursor()
        cursor.execute("EXEC register_staff @username = %s, @email = %s, @fname = %s, @lname = %s, @contact = %s",
                       (username, email, fname, lname, contact))
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
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Staff'):
        return render_template('403.html'), 403
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM get_customer")
    res = cursor.fetchall()
    clean_res = [[(cleanhtml(j) if isinstance(j, str) else j) for j in i] for i in res]
    conn.close()
    return render_template('tables/customertable.html', users=clean_res)


@app.route('/stafftable')
def stafftable():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Manager'):
        return render_template('403.html'), 403
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM get_staff")
    res = cursor.fetchall()
    conn.close()
    clean_res = [[(cleanhtml(j) if isinstance(j, str) else j) for j in i] for i in res]
    return render_template('tables/stafftable.html', users=clean_res)


@app.route('/pendingbookingtable', methods=['GET', 'POST'])
def pendingbookingtable():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Staff'):
        return render_template('403.html'), 403

    approve = ApproveBooking()
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    get_bookings = "SELECT * FROM get_pending_bookings"
    cursor.execute(get_bookings)
    bookings = list(cursor.fetchall())
    conn.close()
    clean_bookings = [[(cleanhtml(j) if isinstance(j, str) else j) for j in i] for i in bookings]
    return render_template('tables/pendingbookingtable.html', bookings=clean_bookings, approve=approve)


@app.route('/deleteBookings', methods=['GET', 'POST'])
def cancelBooking():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Customer'):
        return render_template('403.html'), 403

    delete = deleteBooking()
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    User_UUID = res[0]
    cursor.execute("EXEC get_my_bookings %s", User_UUID)

    bookings = list(cursor.fetchall())
    conn.close()
    return render_template('tables/deletebookings.html', bookings=bookings, delete=delete)


@app.route('/deleteBookingConfirm/<string:id>', methods=['GET', 'POST'])
def deleteBookingConfirm(id):
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Customer'):
        return render_template('403.html'), 403

    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("EXEC delete_bookings %s, %s", (id, res[0]))
    res = cursor.fetchone()

    conn.commit()
    conn.close()

    if res == 1:
        # successfully cancelled
        return render_template('bookings/deletebookingsuccess.html')
    else:
        flash("You cannot cancel any bookings within 7 days", 'danger')
        return redirect(url_for('cancelBooking'))


@app.route('/bookingtable', methods=['GET', 'POST'])
def bookingtable():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] == 'Customer'):
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        User_UUID = res[0]
        cursor.execute("EXEC get_my_bookings %s", User_UUID)
        bookings = cursor.fetchall()
        conn.close()
    elif (res[1] == 'Staff'):
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM get_bookings")
        bookings = cursor.fetchall()
        conn.close()
    else:
        return render_template('403.html'), 403

    clean_bookings = [[(cleanhtml(j) if isinstance(j, str) else j) for j in i] for i in bookings]
    return render_template('tables/bookingtable.html', bookings=clean_bookings)


@app.route('/pendingbookingapprove/<string:id>', methods=['GET', 'POST'])
def pendingBookingApprove(id):
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Staff'):
        return render_template('403.html'), 403

    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("EXEC approve_bookings %s", id)
    conn.commit()
    conn.close()
    return render_template('bookings/bookingapproved.html')


@app.route('/approvedbookingtable', methods=['GET', 'POST'])
def approvedbookingtable():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Staff'):
        return render_template('403.html'), 403
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM get_approved_bookings")
    bookings = cursor.fetchall()
    conn.close()
    return render_template('tables/approvedbookingtable.html', bookings=bookings)


@app.route('/staffupdatesearch', methods=['GET', 'POST'])
def staffUpdateSearch():
    form = StaffSearchForm()
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Manager'):
        return render_template('403.html'), 403
    return render_template('staffCRUD/staff_update_search.html', form=form)


@app.route('/staffupdatevalue', methods=['GET', 'POST'])
def staffUpdateValue():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Manager'):
        return render_template('403.html'), 403
    search_form = StaffSearchForm()
    update_form = StaffUpdateForm()
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    username = encode(search_form.username.data)
    cursor.execute("EXEC staff_details %s", username)
    user = cursor.fetchone()
    if user:
        return render_template('staffCRUD/staff_update_value.html', update_form=update_form, user=user,
                               username=username)
        con.close()
    else:
        flash('No such user found. Please refer to stafftable to find the list of staff users',"danger")
        return render_template('staffCRUD/staff_update_search.html', form=search_form)
    conn.close()

    # return render_template('staffCRUD/staff_update_value.html', update_form=update_form, details=details, username=username)


@app.route('/staffupdatesubmit', methods=['POST'])
def staffUpdateSubmit():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Manager'):
        return render_template('403.html'), 403
    update_form = StaffUpdateForm()
    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")

    username = encode(update_form.username.data)
    email = encode(update_form.email.data)
    fname = encode(update_form.firstname.data)
    lname = encode(update_form.lastname.data)
    address = encode(update_form.address.data)
    DOB = update_form.dob.data
    country = encode(update_form.country.data)
    city = encode(update_form.city.data)
    contact = update_form.contact.data

    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    if update_form.validate_on_submit():
        cursor.execute("EXEC update_details %s, %s, %s, %s, %s, %s, %s, %s, %d",
                       (username, email, fname, lname, address, DOB, country, city, contact))
        conn.commit()
        flash("Edit staff profile successfully", 'success')
        cursor.execute("EXEC user_details %s", username)
        user = cursor.fetchone()
        return render_template('staffCRUD/staff_update_value.html', update_form=update_form, user=user,
                               username=username)
    cursor.execute("EXEC user_details %s", username)
    user = cursor.fetchone()

    return render_template('staffCRUD/staff_update_value.html', update_form=update_form, user=user,
                           username=update_form.username.data)

    # return render_template('staffCRUD/staff_update_sucess.html')


@app.route("/viewProfile", methods=['GET'])
# @login_required  # ensure is logged then, only then can access the dashboard
def viewProfile():
    res = check_session(session['username'], session['Session_ID'])
    if not (res[1] == 'Customer' or res[1] == 'Staff' or res[1] == 'Manager'):
        return render_template('403.html'), 403
    editProfileForm = EditProfileForm()
    changePasswordForm = ChangePasswordForm()
    if "username" in session:
        username = session["username"]
    else:
        return redirect(url_for('timeout'))

    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("EXEC user_details %s", username)
    user = cursor.fetchone()
    conn.close()

    return render_template('customers/editProfile.html', editProfileForm=editProfileForm,
                           changePasswordForm=changePasswordForm, user=user, username=username)


@app.route('/editprofile', methods=['POST'])
def editProfile():
    res = check_session(session['username'], session['Session_ID'])
    if not (res[1] == 'Customer' or res[1] == 'Staff' or res[1] == 'Manager'):
        return render_template('403.html'), 403
    editProfileForm = EditProfileForm()
    changePasswordForm = ChangePasswordForm()

    username = session["username"]
    if editProfileForm.validate_on_submit():
        passwordInput = encode(editProfileForm.password.data)
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()
        cursor.execute('EXEC retrieve_password @username = %s', username)
        passwordHash = cursor.fetchone()
        # Uses bcrypt to check the password hashes and calls the login_user stored procedure to check if login was successful and to update the database accordingly.

        email = encode(editProfileForm.email.data)
        fname = encode(editProfileForm.firstname.data)
        lname = encode(editProfileForm.lastname.data)
        address = encode(editProfileForm.address.data)
        DOB = str(editProfileForm.dob.data)
        country = encode(editProfileForm.country.data)
        city = encode(editProfileForm.city.data)
        contact = editProfileForm.contact.data

        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()

        if bcrypt.check_password_hash(passwordHash[0], passwordInput):
            cursor.execute("EXEC update_details %s, %s, %s, %s, %s, %s, %s, %s, %d",
                           (username, email, fname, lname, address, DOB, country, city, contact))
            conn.commit()
            flash("Edit profile was successful", 'success')
        else:
            flash("Password incorrect. Please try again", "danger")

        redirect(url_for('viewProfile'))

    cursor.execute("EXEC user_details %s", username)
    user = cursor.fetchone()
    conn.close()
    return render_template('customers/editProfile.html', editProfileForm=editProfileForm,
                           changePasswordForm=changePasswordForm, user=user, username=username)


@app.route('/changepassword', methods=['POST'])
def changepassword():
    res = check_session(session['username'], session['Session_ID'])
    if not (res[1] == 'Customer' or res[1] == 'Staff' or res[1] == 'Manager'):
        return render_template('403.html'), 403
    editProfileForm = EditProfileForm()
    changePasswordForm = ChangePasswordForm()
    if "username" in session:
        username = session["username"]
    else:
        return redirect(url_for('timeout'))

    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    cursor.execute("EXEC user_details %s", username)
    user = cursor.fetchone()
    if changePasswordForm.validate_on_submit():
        passwordInput = encode(changePasswordForm.password.data)
        cursor.execute('EXEC retrieve_password @username = %s', username)
        passwordHash = cursor.fetchone()
        # Uses bcrypt to check the password hashes and calls the login_user stored procedure to check if login was successful and to update the database accordingly.
        if bcrypt.check_password_hash(passwordHash[0], passwordInput):
            hashed_password = bcrypt.generate_password_hash(changePasswordForm.password2.data)
            cursor.execute('EXEC update_password %s, %s', (user[2], hashed_password))
            conn.commit()
            flash("Password changed successfully", 'success')
        else:
            flash("Current password incorrect. Please try again", "danger")

        conn.close()
        redirect(url_for('viewProfile'))

    conn.close()
    return render_template('customers/editProfile.html', editProfileForm=editProfileForm,
                           changePasswordForm=changePasswordForm, user=user, username=username)


@app.route('/registersuccess')
# @login_required  # ensure is logged then, only then can log out
def registersuccess():
    return render_template('registersucess.html')


@app.route('/staffregistersucess')
# @login_required  # ensure is logged then, only then can log out
def staffregistersucess():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Manager'):
        return render_template('403.html'), 403
    return render_template('staffregistersucess.html')


@app.route('/staffdeletesearch', methods=['GET', 'POST'])
def staffDeleteSearch():
    form = StaffSearchForm()
    return render_template('staffCRUD/staff_delete_search.html', form=form)


@app.route('/staffdeletesubmit', methods=['GET', 'POST'])
def staffDeleteSubmit():
    return render_template('staffCRUD/staff_update_sucess.html')


@app.route("/timeout")
def timeout():
    hostname = encode(socket.gethostname())
    source_ip = encode(get('https://api.ipify.org').text)
    destination_ip = encode(request.remote_addr)
    browser = str(request.user_agent)
    time_date_aware = datetime.datetime.now(pytz.utc)

    conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
    cursor = conn.cursor()
    insert_stmt = ("EXEC create_log %s, %s, %s, %s, %s, %s, %s, %s")
    data = (time_date_aware, "session_expired", "Warn", hostname, source_ip, destination_ip, browser,
            f"User {session['User_ID']} session timeout")

    cursor.execute(insert_stmt, data)
    conn.commit()
    conn.close()

    delete_session(session['username'], session['Session_ID'])
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


# # To direct to 400 page
# @app.errorhandler(400)
# def unauthorized_page(error):
#     return render_template('400.html'), 400


# # To direct to 401 page
# @app.errorhandler(401)
# def unauthorized_page(error):
#     return render_template('401.html'), 401


# # To direct to 404 page
# @app.errorhandler(404)
# def page_not_found(error):
#     return render_template('404.html'), 404


# # To direct to 500 page
# @app.errorhandler(500)
# def internal_error(error):
#     return render_template('500.html'), 500


# # To direct to CSRF validation error
# @app.errorhandler(CSRFError)
# def handle_csrf_error(error):
#     return render_template('403.html'), 403


# # To handle index error
# @app.errorhandler(IndexError)
# def index_error(error):
#     return render_template('500.html'), 500


# # To handle exception error
# @app.errorhandler(Exception)
# def operational_error(error):
#     return render_template('403.html'), 403


@app.route("/booking", methods=['GET', 'POST'])
# @login_required
def booking():
    res = check_session(session['username'], session['Session_ID'])
    if (res[1] != 'Customer'):
        return render_template('403.html'), 403

    form = BookingForm()
    if form.validate_on_submit():
        # Creating connections individually to avoid open connections
        # CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()

        room_type = form.room_type.data
        start_date = form.start_date.data
        end_date = form.end_date.data

        format = "%Y/%m/%d"
        num_days = end_date - start_date
        num_days = num_days.days

        if room_type == "Standard Twin":
            room_type = 1
            cost = num_days * 200
        elif room_type == "Standard Queen":
            room_type = 2
            cost = num_days * 250
        elif room_type == "Deluxe":
            room_type = 3
            cost = num_days * 500
        else:
            # Default value
            room_type = 1
            cost = num_days * 200

        session['STRIPEpayment'] = cost * 100

        # Send the data to database
        cursor.execute("EXEC setup_booking %s, %d, %s, %s, %s", (res[0], room_type, "", start_date, end_date))

        try:
            res = cursor.fetchone()[0]
        except:
            res = 3

        conn.commit()
        conn.close()
        if res == 1:
            # Booking pending approval
            return render_template('STRIPEpayment/payment.html', room_type_string=form.room_type.data,
                                   room_type_id=room_type, start_date=start_date, end_date=end_date, num_days=num_days,
                                   cost=cost, key=stripe_keys['publishable_key'],
                                   stripe_payment=session['STRIPEpayment'])
        elif res == 2:
            # Database detected that there was no such room available during the date range provided
            flash("Booking failed. No rooms of this type available during date range. Or input error detected")
        elif res == 3:
            # Maximum of 5 bookings allowed for each customer
            flash(
                "You may only have a maximum of 5 bookings.\nTo make more bookings, please delete an existing booking first.")
        else:
            # For logging purposes
            flash("Booking failed. No rooms of this type available during date range. Or input error detected")

    return render_template('bookings/bookroom.html', title='Book Rooms', form=form)


@app.route('/checkout', methods=['POST', 'GET'])
def checkout():
    customer = stripe.Customer.create(
        source=request.form['stripeToken']
    )

    stripe.Charge.create(
        customer=customer.id,
        amount=session['STRIPEpayment'],
        currency='sgd',
        description='Booking Payment'
    )

    amount = session['STRIPEpayment'] / 100

    return render_template('STRIPEpayment/checkout.html', amount=amount)


if __name__ == '__main__':
    app.run(debug=True)
