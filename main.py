# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash
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
login_manager.login_view = "login"
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


@app.route("/login", methods=['GET', 'POST'])  # Specify if we want this function to only perform what methods
def login():
    form = LoginForm()
    # check if the user exists in the database
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # If they are in the database,check for their password hashed,compare with real password. If it matches,
        # then redirect them to dashboard page
        if user:
            if user.role == "Customer":
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('customerdashboard'))

            if user.role == "Staff":
                # if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('staffdashboard'))

            if user.role == "Manager":
                # if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('managerdashboard'))


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
@login_required  # ensure is logged then, only then can log out
def customertable():
    users = User.query.filter_by(role="Customer")
    return render_template('tables/customertable.html', users=users)


@app.route('/stafftable')
@login_required  # ensure is logged then, only then can log out
def stafftable():
    users = User.query.filter_by(role="Staff")
    return render_template('tables/stafftable.html', users=users)


@app.route('/registersuccess')
@login_required  # ensure is logged then, only then can log out
def registersuccess():
    return render_template('registersucess.html')


if __name__ == '__main__':
    app.run(debug=True)
