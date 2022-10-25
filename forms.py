from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField, IntegerField, EmailField, validators, SelectField, \
    DateField
from wtforms.validators import InputRequired, Length, ValidationError, Email, DataRequired
import datetime
from datetime import date
import re


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

    # For users to enter recaptcha field
    recaptcha = RecaptchaField()

    submit = SubmitField("Login")


class CancelReservation(FlaskForm):
    cancelButton = SubmitField("Cancel My Booking")


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
