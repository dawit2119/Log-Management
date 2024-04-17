from flask_wtf import FlaskForm
from flask_wtf.file import FileField,FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField,ValidationError
from wtforms.validators import InputRequired, Length, Email, EqualTo
from database import users_collection
from flask import session

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(message="Please enter username"),
        Length(min=2, max=20, message="Username must be between 5 and 20 characters")
    ])
    email = StringField('Email', validators=[
        InputRequired(message="Please enter email"),
        Email(message="Please enter a valid email.")
    ])
    password = PasswordField('Password', validators=[
        InputRequired(message="Password is required")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(message="Confirm password"),
        EqualTo('password', message="Passwords don't match.")
    ])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = users_collection.find_one({'username': username.data})
        if user:
            raise ValidationError("This username is already taken. Please choose another one.")

    def validate_email(self, email):
        user = users_collection.find_one({'email': email.data})
        if user:
            raise ValidationError("This email is already taken. Please choose another one.")

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[InputRequired(message="Please enter your email"), Email(message="email is Invalid.")])
    password = PasswordField('Password', validators=[InputRequired(message="password is requried.")])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AccountUpdateForm(FlaskForm):
    username = StringField('Username',
                           validators=[InputRequired(message="Please enter username"), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[InputRequired(message="Please enter your email"), Email("email is incorrect")])
    profile_picture = FileField('Update Profile Picture',validators=[FileAllowed(['jpg','png'])])
    submit = SubmitField('Update!')
    def validate_username(self,username):
        if username.data != session.get('username'):
            user = users_collection.find_one({'username':username.data})
            if user:
                raise ValidationError("The Username is already taken. choose another one.")


    def validate_email(self,email):
        if email.data != session.get('email'):
            email =user = users_collection.find_one({'email':email.data})
            if user:
                raise ValidationError("The email is already taken. choose another one.")
