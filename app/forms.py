from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class VendorForm(FlaskForm):
    name = StringField("Vendor Name", validators=[DataRequired(), Length(min=2, max=255)])
    domain = StringField("Vendor Domain (e.g., acme.com)")
    consent = BooleanField("Active-scan consent")
    submit = SubmitField("Save")

class UserForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Temporary Password", validators=[DataRequired(), Length(min=8)])
    role = StringField("Role", validators=[DataRequired(), Length(max=32)])
    submit = SubmitField("Add User")