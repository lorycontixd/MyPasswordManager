from flask_wtf import FlaskForm, Form
from wtforms.validators import DataRequired
from wtforms.widgets import  CheckboxInput, TextInput, html_params, PasswordInput
from wtforms.fields import BooleanField, StringField, PasswordField
from dataclasses import dataclass

def select_multi_checkbox(field, ul_class='', **kwargs):
    kwargs.setdefault('type', 'checkbox')
    field_id = kwargs.pop('id', field.id)
    html = [u'<ul %s>' % html_params(id=field_id, class_=ul_class)]
    for value, label, checked in field.iter_choices():
        choice_id = u'%s-%s' % (field_id, value)
        options = dict(kwargs, name=field.name, value=value, id=choice_id)
        if checked:
            options['checked'] = 'checked'
        html.append(u'<li><input %s /> ' % html_params(**options))
        html.append(u'<label for="%s">%s</label></li>' % (field_id, label))
    html.append(u'</ul>')
    return u''.join(html)


class UpdateObject:
    service: str
    username: str
    password: str

    def __init__(self, service: str, username: str, password: str):
        self.service = service
        self.username = username
        self.password = password



class ViewPasswordForm(Form):
    service = StringField('Service', validators=[DataRequired()], render_kw={'readonly': True})
    username = StringField('Username', validators=[DataRequired()], render_kw={'readonly': True})
    password = StringField('Password', widget=PasswordInput(hide_value=False), render_kw={'readonly': True})
    checkbox = BooleanField("Show password", id="checkbox")

class UpdatePasswordForm(Form):
    service = StringField('Service', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', widget=PasswordInput(hide_value=False))
    #password = PasswordField("Password", id="password",validators=[DataRequired()])
    checkbox = BooleanField("Show password", id="checkbox")


class CreatePasswordForm(Form):
    pass
