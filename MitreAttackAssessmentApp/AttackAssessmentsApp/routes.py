from flask import Flask, url_for, request, redirect, abort, jsonify, render_template, flash
from AttackAssessmentsApp.dbFiles.AaDAO import aaDAO
from AttackAssessmentsApp import app
from AttackAssessmentsApp.forms import RegistrationForm, LoginForm

@app.context_processor
def processor():
    result = aaDAO.getAllTactics()
    tacticsList=[]
    for x in result:
        tacticsList.append(x["tacticName"])
    return dict(tactics=tacticsList)

# taken from https://github.com/CoreyMSchafer/code_snippets/blob/master/Python/Flask_Blog/03-Forms-and-Validation/flaskblog.py
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)

# taken from https://github.com/CoreyMSchafer/code_snippets/blob/master/Python/Flask_Blog/03-Forms-and-Validation/flaskblog.py
@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.email.data == 'admin@blog.com' and form.password.data == 'password':
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/')
def root():
    return render_template('home.html', title="Home")


@app.route('/home')
def home():
    return render_template('home.html', title="Home")

@app.route('/tactics')
def tactics():
    return render_template('tactics.html', title="Tactics")

@app.route('/techniques/<type>')
def techniques(type):
    return render_template('techniques.html', title = f"Techniques: {type}")

@app.route('/adversaries')
def adversaries():
    return render_template('adversaries.html', title="Adversaries")

@app.route('/malware-tools')
def malwareTools():
    return render_template('malware-tools.html', title="Malware / Tools")


@app.route('/api/tactics')
def getAllTactics():
    return jsonify(aaDAO.getAllTactics())

@app.route('/api/attackPatterns')
def getAllAttackPatterns():
    return jsonify(aaDAO.getAllAttackPatterns())

@app.route('/api/adversaries')
def getAllAdversaries():
    return jsonify(aaDAO.getAllAdversaries())

@app.route('/api/malware')
def getAllMalware():
    return jsonify(aaDAO.getAllMalware())

@app.route('/api/<attackID>')
def findByAttackID(attackID):
    return jsonify(aaDAO.findByAttackID(attackID))

@app.route('/api/adversary/<name>')
def getAllAttackIDsByAdversaryName(name):
    return jsonify(aaDAO.getAllAttackIDsByAdversaryName(name, "Actor"))

@app.route('/api/malware/<name>')
def getAllAttackIDsByMalwareName(name):
    return jsonify(aaDAO.getAllAttackIDsByAdversaryName(name, "Malware"))

@app.route('/api/tactics', methods=['POST'])
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
def delete(name):
    aaDAO.delete(name)
    return jsonify({"done": True})


@app.route('/api/updateTacticsAssessments', methods=['PUT'])
def updateTacticsAssessments():
    aaDAO.updateTacticsAssessments()
    return jsonify(aaDAO.getAllTactics())
