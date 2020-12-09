from flask import Flask, url_for, request, redirect, abort, jsonify, render_template, flash
from AttackAssessmentsApp.dbFiles.AaDAO import aaDAO
from AttackAssessmentsApp import app, bcrypt, login_manager
from AttackAssessmentsApp.forms import RegistrationForm, LoginForm
from flask_login import login_user, current_user, logout_user, login_required

import loginManager

global current_user

@app.context_processor
def processor():
    result = aaDAO.getAllTactics()
    tacticsList=[]
    for x in result:
        tacticsList.append(x["tacticName"])
    return dict(tactics=tacticsList)

# https://github.com/CoreyMSchafer/code_snippets/blob/master/Python/Flask_Blog/06-Login-Auth/flaskblog/routes.py
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        aaDAO.createUser(form.email.data, hashed_password)
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

# https://github.com/CoreyMSchafer/code_snippets/blob/master/Python/Flask_Blog/06-Login-Auth/flaskblog/routes.py
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = aaDAO.getUser(form.email.data)
        if user and bcrypt.check_password_hash(user[0][1], form.password.data):
            user = loginManager.User(user[0][0])
            login_user(user, remember=form.remember.data, force=True)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


'''@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))'''


@app.route('/')
@app.route('/home')
@login_required
def home():
    return render_template('home.html', title="Home")

@app.route('/tactics')
@login_required
def tactics():
    return render_template('tactics.html', title="Tactics")

@app.route('/techniques/<type>')
@login_required
def techniques(type):
    return render_template('techniques.html', title = f"Techniques: {type}")

@app.route('/adversaries')
@login_required
def adversaries():
    return render_template('adversaries.html', title="Adversaries")

@app.route('/malware-tools')
@login_required
def malwareTools():
    return render_template('malware-tools.html', title="Malware / Tools")


@app.route('/api/tactics')
@login_required
def getAllTactics():
    return jsonify(aaDAO.getAllTactics())

@app.route('/api/attackPatterns')
@login_required
def getAllAttackPatterns():
    return jsonify(aaDAO.getAllAttackPatterns())

@app.route('/api/adversaries')
@login_required
def getAllAdversaries():
    return jsonify(aaDAO.getAllAdversaries())

@app.route('/api/malware')
@login_required
def getAllMalware():
    return jsonify(aaDAO.getAllMalware())

@app.route('/api/<attackID>')
@login_required
def findByAttackID(attackID):
    return jsonify(aaDAO.findByAttackID(attackID))

@app.route('/api/adversary/<name>')
@login_required
def getAllAttackIDsByAdversaryName(name):
    return jsonify(aaDAO.getAllAttackIDsByAdversaryName(name, "Actor"))

@app.route('/api/malware/<name>')
@login_required
def getAllAttackIDsByMalwareName(name):
    return jsonify(aaDAO.getAllAttackIDsByAdversaryName(name, "Malware"))

@app.route('/api/tactics', methods=['POST'])
@login_required
def createTactic():
    if not request.json:
        abort(400)
    tactic = {
        'attackID':request.json["attackID"],
        'tacticName':request.json["tacticName"],
        'description':request.json["description"],
        'assessment':request.json["assessment"]
        }
    return jsonify(aaDAO.createTactic(tactic))

@app.route('/api/attackPatterns', methods=['POST'])
@login_required
def createAttackPattern():
    if not request.json:
        abort(400)
    pattern = {
        'attackID':request.json["attackID"],
        'patternName':request.json["patternName"],
        'tacticName':request.json["tacticName"],
        'isSubtechnique':request.json["isSubTechnique"],
        'hasSubtechnique':request.json["hasSubtechnique"],
        'description':request.json["description"],
        'assessment':request.json["assessment"]
        }
    return jsonify(aaDAO.createAttackPattern(pattern))


@app.route('/api/adversaries', methods=['POST'])
@login_required
def createAdversary():
    if not request.json:
        abort(400)
    adversary = {
        'name':request.json["name"],
        'description':request.json["description"],
        'inherentRisk':request.json["inherentRisk"],
        'defense':0,
        'residualRisk':0,
        }
    return jsonify(aaDAO.createAdversary(adversary))

@app.route('/api/<attackID>', methods=['PUT'])
@login_required
def update(attackID):
    foundAssessment = aaDAO.findByAttackID(attackID)
    if foundAssessment == {}:
        return jsonify({}), 404
    currentAssessment = foundAssessment
    if 'tacticName' in request.json:
        currentAssessment['tacticName'] = request.json['tacticName']
    if 'patternName' in request.json:
        currentAssessment['patternName'] = request.json['patternName']
    if 'isSubtechnique' in request.json:
        currentAssessment['isSubtechnique'] = request.json['isSubtechnique']
    if 'hasSubtechnique' in request.json:
        currentAssessment['hasSubtechnique'] = request.json['hasSubtechnique']
    if 'description' in request.json:
        currentAssessment['description'] = request.json['description']
    if 'assessment' in request.json:
        currentAssessment['assessment'] = request.json['assessment']
    if attackID[:2] == "TA":
        aaDAO.updateTactic(currentAssessment)
    else:
        aaDAO.updateAttackPattern(currentAssessment)
        aaDAO.updateTacticsAssessments()
    return jsonify(currentAssessment)


@app.route('/api/adversary/<name>', methods=['PUT'])
@login_required
def updateAdversary(name):
    foundAdversary = aaDAO.findAdversaryByName(name)
    if foundAdversary == {}:
        return jsonify({}), 404
    if 'description' in request.json:
        foundAdversary['description'] = request.json['description']
    if 'inherentRisk' in request.json:
        foundAdversary['inherentRisk'] = int(request.json['inherentRisk'])
        foundAdversary['residualRisk'] = foundAdversary['inherentRisk'] * foundAdversary['defense'] / 100
    aaDAO.updateAdversary(foundAdversary)
    return jsonify(foundAdversary)

@app.route('/api/malware/<name>', methods=['PUT'])
@login_required
def updateMalware(name):
    foundAdversary = aaDAO.findMalwareByName(name)
    if foundAdversary == {}:
        return jsonify({}), 404
    if 'description' in request.json:
        foundAdversary['description'] = request.json['description']
    if 'inherentRisk' in request.json:
        foundAdversary['inherentRisk'] = int(request.json['inherentRisk'])
        foundAdversary['residualRisk'] = foundAdversary['inherentRisk'] * foundAdversary['defense'] / 100
    aaDAO.updateMalware(foundAdversary)
    return jsonify(foundAdversary)

@app.route('/api/<name>', methods=['DELETE'])
@login_required
def delete(name):
    aaDAO.delete(name)
    return jsonify({"done": True})


@app.route('/api/updateTacticsAssessments', methods=['PUT'])
@login_required
def updateTacticsAssessments():
    aaDAO.updateTacticsAssessments()
    return jsonify(aaDAO.getAllTactics())


