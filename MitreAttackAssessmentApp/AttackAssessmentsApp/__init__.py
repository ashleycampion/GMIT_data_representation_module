from flask import Flask
from flask_bcrypt import Bcrypt
# see here: https://github.com/maxcountryman/flask-login
from flask_login import LoginManager
app = Flask(__name__, static_url_path='', static_folder='static')
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# place import here to avoid circular imports
from AttackAssessmentsApp import routes