# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy  # to create db and an instance of sql Alchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, validators
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
import pymssql

app = Flask(__name__, static_url_path='/static')  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = 'thisisasecretkey'  # flask uses secret to secure session cookies and protect our webform
# against attacks such as Cross site request forgery (CSRF)
bcrypt = Bcrypt(app)

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

    # For users to choose the employee number
    emp_no = StringField(validators=[InputRequired(),
                                       Length(min=4, max=20)])

    # For users to confirm password
    password_confirm = PasswordField(label='Password confirm', validators=[InputRequired(),
                                                                           validators.Length(min=8, max=32)])

    submit = SubmitField("Register")  # Register button once they are done



class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=32)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(),
                                         Length(min=8, max=64)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


# App routes help to redirect to different pages of the website
@app.route("/", methods=['GET', 'POST'])
def home():
    return render_template('index.html')


@app.route("/login", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def login():
    form = LoginForm()
    # check if the user exists in the database
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        
        #Creating connections individually to avoid open connections
        #CHANGE TO YOUR OWN MSSQL SERVER PLEASE
        conn = pymssql.connect("DESKTOP-7GS9BE8", 'sa', '12345678', "3203")
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
            #Add code her with Flask-Authorize to determine the role of the user and redirect accordingly
            return redirect(url_for('customerdashboard'))
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('login.html', form=form)

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
        conn = pymssql.connect("DESKTOP-7GS9BE8", 'sa', '12345678', "3203")

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

@app.route("/staffregister", methods=['GET', 'POST'])
def staffregister():
    form = RegisterForm()
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_customer = User(firstname=form.firstname.data, lastname=form.lastname.data,
                            email=form.email.data, username=form.username.data,
                            password=hashed_password, contact=form.contact.data,
                            emp_no=form.emp_no.data,role="Staff")
        db.session.add(new_customer)
        db.session.commit()
        return redirect(url_for('staffregistersucess'))  # redirect to login page after register

    # if account creation is successful, go to login page, else flash message to user
    if request.method == 'POST':
        if form.validate():
            return redirect(url_for('staffregistersucess'))
        else:
            # Check if username already exists in database and return error message
            existing_user_username = User.query.filter_by(username=form.username.data).first()
            if existing_user_username:
                flash("This username already exists. Please choose a different one.")

            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                flash("This email already exists in the system. Please register with another.")

    return render_template('staffregister.html', form=form)


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

@app.route('/staffregistersucess')
@login_required  # ensure is logged then, only then can log out
def staffregistersucess():
    return render_template('staffregistersucess.html')


if __name__ == '__main__':
    app.run(debug=True)
