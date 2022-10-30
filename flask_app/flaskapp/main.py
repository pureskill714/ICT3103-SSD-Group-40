# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
import os

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, validators
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, CSRFError
import pymssql
from flask import Blueprint, render_template
mainapp = Blueprint('', __name__, url_prefix='/')



sql_pass = os.environ['MSSQL_SA_PASSWORD']

app = Flask(__name__, static_url_path='/static')  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = 'thisisasecretkey'  # flask uses secret to secure session cookies and protect our webform
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdMHXAiAAAAACouP_eGKx_x6KYgrAwnPIQUIpNe'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdMHXAiAAAAAP3uAfsgPERmaMdA9ITnVIK1vn9W'
# against attacks such as Cross site request forgery (CSRF)
bcrypt = Bcrypt(app)

csrf = CSRFProtect(app) #globally enable csrf protection within the application

# Handling the login validation for Customers
login_manager = LoginManager()  # Allow our app and flask login to work together
# login_manager.init_app(app)
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

    submit = SubmitField("Register")  # Register button once they are done

# App routes help to redirect to different pages of the website
@mainapp.route("/", methods=['GET', 'POST'])
def home():
    return render_template('index.html')

def encode(input):
    #Function that checks if the user inputs can be encoded and decoded to and from utf-8
    #Can help to prevent buffer overflow/code injection/
    try:
        return input.encode('utf-8', 'strict').decode('utf-8', 'strict')
    except UnicodeDecodeError:
        return None

@mainapp.route("/login", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def login():
    form = LoginForm()
    if form.validate_on_submit():
        
        #Creating connections individually to avoid open connections
        #CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect(server="db", user='sa', password=sql_pass, database="3203")
        cursor = conn.cursor()

        #Prevent users from entering non-ascii encoded characters
        #username = form.username.data.encode(encoding="ascii", errors="ignore")
        #print(username)

        #Run encode/decode check functions
        passwordInput = encode(form.password.data)
        username = encode(form.username.data)

        #If either values are None, then the user input could not be encoded into UTF-8
        if passwordInput is None or username is None:
            flash("Please check your user inputs again.")
            return render_template('login.html', form=form)

        #Fetches original password hash of the user and compares the hash with the password provided using bcrypt
        cursor.execute('EXEC retrieve_password @username = %s', (username))
        passwordHash = cursor.fetchone()

        #Uses bcrypt to check the password hashes and calls the login_user stored procedure to check if login was successful and to update the database accordingly.
        try:
            passResult = bcrypt.check_password_hash(passwordHash, passwordInput)
        except:
            #Would likely occur if there was user had keyed in an invalid username
            flash("Username or Password incorrect. Please try again")
            passResult = 0

        #res = cursor.callproc('login_user', (username, int(passResult), request.remote_addr, pymssql.output(str), pymssql.output(int),))

        cursor.execute("EXEC login_user @username = %s, @login_success = %d, @IP_Address = %s", (username, int(passResult), request.remote_addr))
        conn.commit()
        conn.close()

        try:
            res = cursor.fetchone()
            user_email = res[0]
            role_ID = res[1]
        except:
            # Login failed, so no user email or role ID returned to res
            user_email = None
            role_ID = None
        
        if user_email is not None: #Login was successful
            #Add code her with Flask-Authorize to determine the role of the user and redirect accordingly
            if role_ID == 1:
                return redirect(url_for('customerdashboard'))
            elif role_ID == 2:
                return redirect(url_for('managerdashboard'))
            else:
                return render_template('login.html', form=form)
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('login.html', form=form)

@mainapp.route("/customerdashboard", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can access the dashboard
def customerdashboard():
    return render_template('dashboards/customerdashboard.html')

@mainapp.route("/staffdashboard", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can access the dashboard
def staffdashboard():
    return render_template('dashboards/staffdashboard.html')

@mainapp.route("/managerdashboard", methods=['GET', 'POST'])
#@login_required  # ensure is logged then, only then can access the dashboard
def managerdashboard():
    return render_template('dashboards/managerdashboard.html')


@mainapp.route("/logout", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can log out
def logout():
    logout_user()  # log the user out
    return redirect(url_for('login'))  # redirect user back to login page


@mainapp.route("/forgetPassword", methods=['GET', 'POST'])
def forgetPassword():
    logout_user()  # log the user out
    return render_template('forgetpassword.html')


@mainapp.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        #Creating connections individually to avoid open connections
        #CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect(server='db', user='sa', password=sql_pass, database="3203")

        #Run encode/decode check functions
        passwordInput = encode(form.password.data)
        username = encode(form.username.data)
        email = encode(form.email.data)
        fname = encode(form.firstname.data)
        lname = encode(form.lastname.data)

        #Verifies that there are no issues with encoding
        if passwordInput is None or username is None or email is None or fname is None or lname is None:
            flash("Please check your user inputs again.")
            return render_template('register.html', form=form)

        hashed_password = bcrypt.generate_password_hash(passwordInput)
        cursor = conn.cursor()

        #The old procedure for registration via running the stored procedure, not sure which method is better
        #args = (str(form.username.data), hashed_password, form.email.data, form.firstname.data, form.lastname.data, pymssql.output(int),)
        #print(args)
        #res = cursor.callproc('register_customer', args)

        #Execute statement for running the stored procedure
        #Raw inputs are formatted and parameterized into a prepared statement
        cursor.execute("EXEC register_customer @username = %s, @password = %s, @email = %s, @fname = %s, @lname = %s", (username, hashed_password, email, fname, lname))
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

    return render_template('register.html', form=form)

@app.route("/staffregister", methods=['GET', 'POST'])
def staffregister():
    form = StaffRegisterForm()
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        #Creating connections individually to avoid open connections
        #CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("db", 'sa', sql_pass, "3203")

        #Run encode/decode check functions
        username = encode(form.username.data)
        email = encode(form.email.data)
        fname = encode(form.firstname.data)
        lname = encode(form.lastname.data)
        #contact = encode(form.contact.data)

        if username is None or email is None or fname is None or lname is None:
            flash("Please check your user inputs again.")
            return render_template('register.html', form=form)
        
        cursor = conn.cursor()
        cursor.execute("EXEC register_staff @username = %s, @email = %s, @fname = %s, @lname = %s", (username, email, fname, lname))
        res = cursor.fetchone()[0]
        conn.commit()
        conn.close()

        #Generate a reset password link and send it to the email used to create the account. 
        #Since the account has no valid password assigned to it, this password link must not check if the user knows the old password.
        
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

@mainapp.route('/customertable')
def customertable():
    return render_template('tables/customertable.html')

@mainapp.route('/stafftable')
def stafftable():
    return render_template('tables/stafftable.html')

@mainapp.route('/staffupdatesearch', methods=['GET', 'POST'])
def staffUpdateSearch():
    return render_template('staffCRUD/staff_update_search.html')

@mainapp.route('/staffupdatevalue', methods=['GET', 'POST'])
def staffUpdateValue():
    return render_template('staffCRUD/staff_update_value.html')

@mainapp.route('/staffupdatesubmit', methods=['GET', 'POST'])
def staffUpdateSubmit():
    return render_template('staffCRUD/staff_update_sucess.html')

@mainapp.route('/registersuccess')
@login_required  # ensure is logged then, only then can log out
def registersuccess():
    return render_template('registersucess.html')

@mainapp.route('/staffregistersucess')
@login_required  # ensure is logged then, only then can log out
def staffregistersucess():
    return render_template('staffregistersucess.html')

# 400 - To handle Bad request
@mainapp.route('/400')
def error400():
    abort(400)

# 401 - To handle error of Unauthorized request
@mainapp.route('/401')
def error401():
    abort(401)

# 404 - To handle error in matching the Request URL
@mainapp.route('/404')
def error404():
    abort(404)

# 500 - To handle error in Internal Server Error
@mainapp.route('/500')
def error500():
    abort(500)

# To direct to 400 page
@mainapp.errorhandler(400)
def unauthorized_page(error):
    return render_template('400.html'), 400
    
# To direct to 401 page
@mainapp.errorhandler(401)
def unauthorized_page(error):
    return render_template('401.html'), 401
    
# To direct to 404 page
@mainapp.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

# To direct to 500 page
@mainapp.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# To direct to CSRF validation error
@mainapp.errorhandler(CSRFError)
def handle_csrf_error(error):
    return render_template('403.html'), 403

if __name__ == '__main__':
    app.run()
