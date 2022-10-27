# from google API part 1, must put future import at start
from __future__ import print_function # not sure if can remove this

# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy  # to create db and an instance of sql Alchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, validators
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, CSRFError
import pymssql

# import library for OTP
import math, random

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

from flask import session

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
# os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "path_to_your_.json_credential_file"

# for logging with a confide to put in date and time before the message logging
import logging
logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')



app = Flask(__name__, static_url_path='/static')  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = 'thisisasecretkey'  # flask uses secret to secure session cookies and protect our webform
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdMHXAiAAAAACouP_eGKx_x6KYgrAwnPIQUIpNe'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdMHXAiAAAAAP3uAfsgPERmaMdA9ITnVIK1vn9W'
# against attacks such as Cross site request forgery (CSRF)

# sessiontest
# app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

bcrypt = Bcrypt(app)

csrf = CSRFProtect(app) #globally enable csrf protection within the application

# function to generate OTP
def generateOTP() :

	# Declare a string variable, only digits in this case
	string = '0123456789'
	sixotp = ""
	length = len(string)
	for i in range(6) :
		sixotp += string[math.floor(random.random() * length)]

	return sixotp


def gmail_send_message(otp, emailadd):

    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    directory = os.getcwd()
    print("this is the directory " + directory)
    x = directory+ "\\token.json"
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

#not sure what this does, can we remove?
@login_manager.user_loader
def load_user_customer(user_id):
    return 1
 
class RegisterForm(FlaskForm):
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
    # For users to choose a password
    password = PasswordField(label='Password', validators=[InputRequired(),
                                                           validators.Length(min=8, max=64),
                                                           validators.EqualTo('password_confirm',
                                                                              message='Passwords must match,Please try again')])

    # For users to confirm password
    password_confirm = PasswordField(label='Password confirm', validators=[InputRequired(),
                                                                           validators.Length(min=8, max=32)])

    submit = SubmitField("Register")  # Register button once they are done



class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=32)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(),
                                         Length(min=8, max=64)], render_kw={"placeholder": "Password"})


    #For users to enter recaptcha field
    recaptcha = RecaptchaField()
    
    submit = SubmitField("Login")

class MfaForm(FlaskForm):
    #For users to enter otp
    mfa = StringField(validators=[InputRequired(), Length(min=6, max=6)])

    

# App routes help to redirect to different pages of the website
@app.route("/", methods=['GET', 'POST'])
def home():
    session.pop('username', None)
    if 'username' in session:
        return f'Logged in as {session["username"]}'

    return render_template('index.html')


@app.route("/login", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def login():
    form = LoginForm()
    # check if the user exists in the database
    if form.validate_on_submit():
        print("LOGGING WORKS THOOO")
        logging.warning('Watch out!')
        session["username"] = request.form.get(form.username.data)
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        
        #Creating connections individually to avoid open connections
        #CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")
        cursor = conn.cursor()


        #Fetches original password hash of the user
        #Might replace this execute command with a function for higher security
        cursor.execute('SELECT Password FROM Users WHERE Username = %s', form.username.data) 

        #Uses bcrypt to check the password hashes and calls the login_user stored procedure to 
        res = cursor.callproc('login_user', (form.username.data, (int(bcrypt.check_password_hash(cursor.fetchone()[0], form.password.data))), request.remote_addr, pymssql.output(str), pymssql.output(int)))
        
        conn.commit()
        conn.close()

        user_email = res[3] #used for MFA function
        role_ID = res[4] #used for Flask-Authorize to properly authorize users

        if user_email is not None: #Login was successful
            # code for sending the otp
            print("logged in liao")
            session['username'] = request.form['username']
           
            generated = generateOTP()
            # when session is created need declare variable here // session['generatedOTP'] = 'my_value'
            print(generated)
            print(user_email)
            gmail_send_message(generated, user_email)
            #Add code her with Flask-Authorize to determine the role of the user and redirect accordingly
            return redirect(url_for('mfa'))
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('login.html', form=form)


@app.route("/mfa", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
#@login_required  # ensure is logged then, only then can access the dashboard
def mfa():

    form = MfaForm()

    # check if the user exists in the database
    if form.validate_on_submit():
        print(form.mfa.data)
        # print("MFA CHECKING")
        
        if form.mfa.data == "123456":
            # print("MFA CHECKED")
            return redirect("index.html")
        else:
            #currently unable to flash this for some reason, it flashes on login screen instead :/
            flash("MFA incorrect. Please try again")

    return render_template('mfa.html', form=form)

@app.route("/customerdashboard", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can access the dashboard
def customerdashboard():
    return render_template('dashboards/customerdashboard.html')

@app.route("/staffdashboard", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can access the dashboard
def staffdashboard():
    return render_template('dashboards/staffdashboard.html')

@app.route("/managerdashboard", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can access the dashboard
def managerdashboard():
    return render_template('dashboards/managerdashboard.html')


@app.route("/logout", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can log out
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
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        #Creating connections individually to avoid open connections
        #CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-M4AHTC3", 'sa', '12345678', "3203")

        cursor = conn.cursor()
        
        #Procedure for registration
        res = cursor.callproc('register_customer', (form.username.data, hashed_password, form.email.data, form.firstname.data, form.lastname.data, pymssql.output(int),))
        
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
@login_required  # ensure is logged then, only then can log out
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

if __name__ == '__main__':
    app.run(debug=True)

############################################################################################