# Allow users to pass variables into our view function and then dynamically change what we have on our view page
# Dynamically pass variables into the URL
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy  # to create db and an instance of sql Alchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)  # Create an instance of the flask app and put in variable app
app.config['SECRET_KEY'] = 'thisisasecretkey'  # flask uses secret to secure session cookies and protect our webform
# against attacks such as Cross site request forgery (CSRF)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # stored in folder called tmp
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()  # Allow our app and flask login to work together
login_manager.init_app(app)
login_manager.login_view = "login"


# This user loaded callback is used to reload the user object from the user id stored in the session
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


# a class as a model. The model will represent the data that will be stored in the database
# this class needs to inherit from db.Model
class Users(db.Model, UserMixin):  # UserMixin is for validating users
    id = db.Column(db.Integer, primary_key=True)  # This will be primary key
    username = db.Column(db.String(30), nullable=False, unique=True)  # username field is unique
    password = db.Column(db.String(80), nullable=False)  # password field


class RegisterForm(FlaskForm):
    # For users to choose a username
    username = StringField(validators=[InputRequired(),
                                       Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    # For users to choose a password
    password = PasswordField(validators=[InputRequired(),
                                         Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")  # Register button once they are done

    # This method checks if there already has an existing username in the database
    def validate_username(self, username):
        # This variable query the database table by the username and check if got same username or not
        existing_user_username = Users.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("This username already exists. Please choose a different one.")


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
        user = Users.query.filter_by(username=form.username.data).first()
        # If they are in the database,check for their password hashed,compare with real password. If it matches,
        # then redirect them to dashboard page
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route("/dashboard", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can access the dashboard
def dashboard():
    return render_template('dashboard.html')


@app.route("/logout", methods=['GET', 'POST'])
@login_required  # ensure is logged then, only then can log out
def logout():
    logout_user()  # log the user out
    return redirect(url_for('login'))  # redirect user back to login page


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # Whenever we submit this form, we immediately create a hash version of the password and submit to database
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = Users(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))  # redirect to login page after register

    # if account creation is successful, go to login page, else flash message to user
    if request.method == 'POST':
        if form.validate():
            return redirect(url_for('login'))
        else:
            flash('Username has been taken. Please choose another username')
    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
