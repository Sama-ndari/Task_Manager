from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.fields.simple import BooleanField
from wtforms.validators import DataRequired, URL


class RegisterForm(FlaskForm):
    name = StringField(label="", validators=[DataRequired()],
                       render_kw={"placeholder": "Enter your Name here"})
    email = StringField(label="", validators=[DataRequired()],
                        render_kw={"placeholder": "Enter your Email here"})
    password = PasswordField(label="", validators=[DataRequired()],
                             render_kw={"placeholder": "Enter your Password here"})
    submit = SubmitField("REGISTER ME UP")


class LoginForm(FlaskForm):
    email = StringField(label="", validators=[DataRequired()],
                        render_kw={"placeholder": "Enter your Email here"})
    password = PasswordField(label="", validators=[DataRequired()],
                             render_kw={"placeholder": "Enter your Password here",  "class": "password-field"})
    remember = BooleanField('Remember Me')
    submit = SubmitField("SIGN ME UP")


class ListForm(FlaskForm):
    name = StringField(label="", validators=[DataRequired()],
                       render_kw={"placeholder": "Name"})
    submit = SubmitField("Create List")


class TaskForm(FlaskForm):
    title = StringField(label="", validators=[DataRequired()],
                        render_kw={"placeholder": "Title"})
    description = StringField(label="",
                              render_kw={"placeholder": "Description"})
    submit = SubmitField("Create Task")
