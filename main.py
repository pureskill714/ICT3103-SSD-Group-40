# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy  # to create db and an instance of sql Alchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, validators
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt

app = Flask(__name__, static_url_path='/static')  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = 'thisisasecretkey'  # flask uses secret to secure session cookies and protect our webform
# against attacks such as Cross site request forgery (CSRF)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Handling the login validation for Customers
login_manager = LoginManager()  # Allow our app and flask login to work together
login_manager.init_app(app)
login_manager.login_view = "customerlogin"
login_manager.login_message = u"Username or Password incorrect. Please try again"


# This user loaded callback is used to reload the user object from the user id stored in the session
@login_manager.user_loader
def load_user_customer(user_id):
    return User.query.get(user_id)


# a class as a model. The model will represent the data that will be stored in the database
# this class needs to inherit from db.Model
class User(db.Model, UserMixin):  # UserMixin is for validating users
    id = db.Column(db.Integer, primary_key=True)  # This will be primary key
    firstname = db.Column(db.String(30), nullable=False)
    lastname = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    username = db.Column(db.String(30), nullable=False, unique=True)  # username field is unique
    password = db.Column(db.String(80), nullable=False)  # password field
    contact = db.Column(db.Integer(), nullable=False)
    role = db.Column(db.String(30), nullable=False)
    emp_no = db.Column(db.Integer(), nullable=True)


class RegisterForm(FlaskForm):
    # For users to choose a first name
    firstname = StringField(validators=[InputRequired(),
                                        Length(min=4, max=20)])
    # For users to choose a last name
    lastname = StringField(validators=[InputRequired(),
                                       Length(min=4, max=20)])

    # For users to input their email
    email = EmailField(validators=[InputRequired("Please enter email address"),
                                   Length(min=4, max=40), Email()])

    # For users to choose a username
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=20)])
    # For users to choose a password
    password = PasswordField(label='Password', validators=[InputRequired(),
                                                           validators.Length(min=6, max=10),
                                                           validators.EqualTo('password_confirm',
                                                                              message='Passwords must match,Please try again')])

    # For users to confirm password
    password_confirm = PasswordField(label='Password confirm', validators=[InputRequired(),
                                                                           validators.Length(min=6, max=10)])

    # For users to enter their contact number
    contact = IntegerField(validators=[InputRequired()])

    submit = SubmitField("Register")  # Register button once they are done

    # This method checks if there already has an existing username in the database
    def validate_username(self, username):
        # This variable query the database table by the username and check if got same username or not
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("This username already exists. Please choose a different one.")

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("This email already exists in the system. Please register with another")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(),
                                         Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


# App routes help to redirect to different pages of the website
@app.route("/", methods=['GET', 'POST'])
def home():
    return render_template('index.html')


@app.route("/customerlogin", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def customerlogin():
    form = LoginForm()
    # check if the user exists in the database
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, role="Customer").first()
        # If they are in the database,check for their password hashed,compare with real password. If it matches,
        # then redirect them to dashboard page
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('customerdashboard'))
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('logins/customerlogin.html', form=form)


@app.route("/stafflogin", methods=['GET', 'POST'])
def stafflogin():
    form = LoginForm()

    # check if the user exists in the database
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, role="Staff").first()
        # If they are in the database,check for their password hashed,compare with real password. If it matches,
        # then redirect them to dashboard page
        if user:
            # if bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('staffdashboard'))
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('logins/stafflogin.html', form=form)


@app.route("/managerlogin", methods=['GET', 'POST'])
def managerlogin():
    form = LoginForm()
    # check if the user exists in the database
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, role="Manager").first()
        # If they are in the database,check for their password hashed,compare with real password. If it matches,
        # then redirect them to dashboard page
        if user:
            # if bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('managerdashboard'))
        else:
            flash("Username or Password incorrect. Please try again")

    return render_template('logins/managerlogin.html', form=form)


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
    return redirect(url_for('customerlogin'))  # redirect user back to login page


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
        new_customer = User(firstname=form.firstname.data, lastname=form.lastname.data,
                            email=form.email.data, username=form.username.data,
                            password=hashed_password, contact=form.contact.data,
                            role="Customer")
        db.session.add(new_customer)
        db.session.commit()
        return redirect(url_for('registersuccess'))  # redirect to login page after register

    # if account creation is successful, go to login page, else flash message to user
    if request.method == 'POST':
        if form.validate():
            return redirect(url_for('registersuccess'))
        else:
            # Check if username already exists in database and return error message
            existing_user_username = User.query.filter_by(username=form.username.data).first()
            if existing_user_username:
                flash("This username already exists. Please choose a different one.")

            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                flash("This email already exists in the system. Please register with another.")

    return render_template('register.html', form=form)


@app.route('/customertable')
def customertable():
    users = User.query.filter_by(role="Customer")
    return render_template('tables/customertable.html', users=users)


@app.route('/stafftable')
def stafftable():
    users = User.query.filter_by(role="Staff")
    return render_template('tables/stafftable.html', users=users)


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

if __name__ == '__main__':
    app.run(debug=True)
