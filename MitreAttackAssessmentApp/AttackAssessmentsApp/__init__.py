from flask import Flask
app = Flask(__name__, static_url_path='', static_folder='static')
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
from AttackAssessmentsApp import routes