# https://github.com/maxcountryman/flask-login
# https://github.com/CoreyMSchafer/code_snippets/blob/master/Python/Flask_Blog/06-Login-Auth/flaskblog/models.py
# https://github.com/CoreyMSchafer/code_snippets/blob/master/Python/Flask_Blog/06-Login-Auth/flaskblog/routes.py

import flask_login
from flask_login import UserMixin
from AttackAssessmentsApp import login_manager, bcrypt
from AttackAssessmentsApp.dbFiles.AaDAO import aaDAO

# there is little advantage from inheriting from UserMixin
# as we need to use a constructor and over ride the get_id method
class User():
    # because we are not using SQLAlchemy,
    # we can use the email as the is Flask
    # associates with the user. Thus we need
    # a constructor
    def __init__(self, email):
        self.id = aaDAO.getUser(email)[0][0]

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False
    
    # this will be called when the user is needed to flask-login
    def get_id(self):
        try:
            return self.id
        except AttributeError:
            raise NotImplementedError('No `id` attribute - override `get_id`')

# this will be called by @login_required decorator
@login_manager.user_loader
def user_loader(email):
    current = aaDAO.getUser(email)
    if not current:
        return None
    user = User(email)
    user.id = email
    return user

# do not comment this out
'''@login_manager.request_loader
def request_loader(request):
    email = request.form.get('email')
    current = aaDAO.getUser(email)
    if not current:
        return None
    user = User(email)
    user.id = email
    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    #user.is_authenticated = (request.form['password'] == current[0][1])
    user.is_authenticated = bcrypt.check_password_hash(current[0][1], request.form['password'])
    return user'''