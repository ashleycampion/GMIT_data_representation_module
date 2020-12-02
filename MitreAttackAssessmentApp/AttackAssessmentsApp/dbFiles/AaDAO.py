import mysql.connector
from AttackAssessmentsApp.dbFiles import config as cfg
from AttackAssessmentsApp.dbFiles import createDB as createDB
from AttackAssessmentsApp.dbFiles.createTables import tableCreator as tableCreator

class AaDAO:
    db = ""
    def __init__(self):
        self.db = mysql.connector.connect(
            host=cfg.ms['host'],
            user=cfg.ms['username'],
            password=cfg.ms['password'],
            database=cfg.ms['database']
        )
        print("Connection made to AttackAssessment database.")


    def createTactic(self, tactic):
        cursor = self.db.cursor()
        sql = "insert into tactics (attackID, tacticName, description, assessment) values (%s, %s, %s, %s)"
        values = [
            tactic['attackID'],
            tactic['tacticName'],
            tactic['description'],
            tactic['assessment'],
        ]
        cursor.execute(sql, values)
        self.db.commit()
        return cursor.lastrowid

    def createAttackPattern(self, pattern):
        cursor = self.db.cursor()
        sql = "insert into attackPatterns (attackID, patternName, tacticName, isSubtechnique, hasSubtechnique, description, assessment) values (%s, %s, %s, %s, %s, %s, %s)"
        values = [
            pattern['attackID'],
            pattern['patternName'],
            pattern['tacticName'],
            pattern['isSubtechnique'],
            pattern['hasSubtechnique'],
            pattern['description'],
            pattern['assessment'],
        ]
        cursor.execute(sql, values)
        self.db.commit()
        return cursor.lastrowid    

    def createAdversary(self, adversary):
        cursor = self.db.cursor()
        sql = "insert into adversaries (name, description, inherentRisk, defense, residualRisk) values (%s, %s, %s, %s, %s)"
        values = [
            adversary['name'],
            adversary['description'],
            adversary['inherentRisk'],
            adversary['defense'],
            adversary['residualRisk'],
        ]
        cursor.execute(sql, values)
        self.db.commit()
        return cursor.lastrowid

    def createMalware(self, malware):
        cursor = self.db.cursor()
        sql = "insert into malware (name, description, inherentRisk, defense, residualRisk) values (%s, %s, %s, %s, %s)"
        values = [
            malware['name'],
            malware['description'],
            malware['inherentRisk'],
            malware['defense'],
            malware['residualRisk'],
        ]
        cursor.execute(sql, values)
        self.db.commit()
        return cursor.lastrowid

    '''def createAdversaryTechniquesTable(self, adversary):
        cursor = self.db.cursor()
        #backticks required for table-names with spaces
        sql = f"create table `{adversary}` (attackID varchar(30));"
        cursor.execute(sql)
        return

    def createAdversaryTechnique(self, adversary, attackID):
        cursor = self.db.cursor()
        sql = f"insert into `{adversary}` (attackID) values ('{attackID}');"
        cursor.execute(sql)
        self.db.commit()
        return cursor.lastrowid


    def createTechniqueAdversariesTable(self, technique):
        cursor = self.db.cursor()
        sql = f"create table `{technique}` (adversary varchar(30));"
        cursor.execute(sql)
        return

    def createTechniqueAdversary(self, technique, adversary):
        cursor = self.db.cursor()
        sql = f"insert into `{technique}` (adversary) values ('{adversary}');"
        cursor.execute(sql)
        self.db.commit()
        return cursor.lastrowid'''

###############################################################
    def createTechniquesOfAdversaryTable(self, user, type):
        cursor = self.db.cursor()
        #backticks required for table-names with spaces
        sql = f"create table `{type}:{user}` (attackID varchar(30));"
        cursor.execute(sql)
        return

    def createTechniqueOfAdversary(self, user, attackID, type):
        cursor = self.db.cursor()
        sql = f"insert into `{type}:{user}` (attackID) values ('{attackID}');"
        cursor.execute(sql)
        self.db.commit()
        return cursor.lastrowid

    def createAdversaryUsingTechniqueTable(self, technique):
        cursor = self.db.cursor()
        sql = f"create table `{technique}` (user varchar(30), type varchar(10));"
        cursor.execute(sql)
        return

    def createAdversaryUsingTechnique(self, technique, user, type):
        cursor = self.db.cursor()
        sql = f"insert into `{technique}` (user, type) values ('{user}', '{type}');"
        cursor.execute(sql)
        self.db.commit()
        return cursor.lastrowid
##########################################################

    def getAllTactics(self):
        cursor = self.db.cursor()
        sql = "select * from tactics"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertTacticToDict(result)
            resultArray.append(resultAsDict)
        return resultArray

    def getAllAttackPatterns(self):
        cursor = self.db.cursor()
        sql = "select * from attackPatterns"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertPatternToDict(result)
            resultArray.append(resultAsDict)
        return resultArray

    def getAllAdversaries(self):
        cursor = self.db.cursor()
        sql = "select * from adversaries"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertAdversaryToDict(result)
            resultArray.append(resultAsDict)
        return resultArray


    def getAllMalware(self):
        cursor = self.db.cursor()
        sql = "select * from malware"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertAdversaryToDict(result)
            resultArray.append(resultAsDict)
        return resultArray


    def getAllAdversariesByAttackID(self, attackID):
        cursor = self.db.cursor()
        sql = f"select adversary from `{attackID}`"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for i in results:
            resultArray.append(i[0])
        return resultArray
    

    def getAllAttackIDsByAdversaryName(self, user, type):
        cursor = self.db.cursor()
        sql = f"select attackID from `{type}:{user}`"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for i in results:
            resultArray.append(i[0])
        return resultArray

    def findAdversaryByName(self, name):
        cursor = self.db.cursor()
        sql = "select * from adversaries where name = %s"
        values = [name]
        cursor.execute(sql, values)
        result = cursor.fetchone()
        if result:
            return self.convertAdversaryToDict(result)

########################################################################



    '''def getAllAdversariesByAttackID(self, attackID, type):
        cursor = self.db.cursor()
        sql = f"select adversary from `{attackID}` where type = {type}"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for i in results:
            resultArray.append(i[0])
        return resultArray'''
    



##########################################################



    def findMalwareByName(self, name):
        cursor = self.db.cursor()
        sql = "select * from malware where name = %s"
        values = [name]
        cursor.execute(sql, values)
        result = cursor.fetchone()
        if result:
            return self.convertAdversaryToDict(result)


    def findByAttackID(self, attackID):
        cursor = self.db.cursor()
        if attackID[:2] == "TA":
            sql = "select * from tactics where AttackID = %s"
            values = [attackID]
            cursor.execute(sql, values)
            result = cursor.fetchone()
            if result:
                return self.convertTacticToDict(result)
        else:
            sql = "select * from attackPatterns where AttackID = %s"
            values = [attackID]
            cursor.execute(sql, values)
            result = cursor.fetchone()
            if result:
                return self.convertPatternToDict(result)
        
    
    
    def updateTactic(self, tactic):
        cursor = self.db.cursor()
        sql = "update tactics set tacticName = %s, description = %s, assessment = %s where attackID = %s"
        values = [
            tactic['tacticName'],
            tactic['description'],
            tactic['assessment'],
            tactic['attackID']
        ]
        cursor.execute(sql, values)
        self.db.commit()
        return tactic

    def updateAttackPattern(self, pattern):
        cursor = self.db.cursor()
        oldDefense = self.findByAttackID(pattern['attackID'])['assessment']
        sql = "update attackPatterns set patternName = %s, tacticName = %s, isSubtechnique = %s, hasSubtechnique = %s, description = %s, assessment = %s where attackID = %s"
        values = [
            pattern['patternName'],
            pattern['tacticName'],
            pattern['isSubtechnique'],
            pattern['hasSubtechnique'],
            pattern['description'],
            pattern['assessment'],
            pattern['attackID']
        ]
        cursor.execute(sql, values)
        self.db.commit()
        self.updateAllAdversariesOneTechnique(pattern['attackID'], oldDefense, int(pattern['assessment']))
        return pattern

    def updateAdversary(self, adversary):
        cursor = self.db.cursor()
        sql = "update adversaries set description = %s, inherentRisk = %s, defense = %s, residualRisk = %s where name = %s"
        values = [
            adversary['description'],
            adversary['inherentRisk'],
            adversary['defense'],
            adversary['residualRisk'],
            adversary['name']
            ]
        cursor.execute(sql, values)
        self.db.commit()
        return adversary



    def updateMalware(self, malware):
        cursor = self.db.cursor()
        sql = "update malware set description = %s, inherentRisk = %s, defense = %s, residualRisk = %s where name = %s"
        values = [
            malware['description'],
            malware['inherentRisk'],
            malware['defense'],
            malware['residualRisk'],
            malware['name']
            ]
        cursor.execute(sql, values)
        self.db.commit()
        return malware


    def updateTacticsAssessments(self):
        for tactic in self.getAllTactics():
            assessmentList=[]
            tacticName = tactic["tacticName"]
            for attackPattern in self.getAllAttackPatterns():
                if attackPattern["tacticName"].split("-")[0] == tacticName.lower().split()[0]:
                    assessmentList.append(attackPattern["assessment"])
            try:
                assessment = sum(assessmentList)/len(assessmentList)
            except ZeroDivisionError:
                continue
            tactic["assessment"] = assessment
            self.updateTactic(tactic)
        return int(tactic["assessment"])


#use technique to group instead
    '''def updateAllAdversariesOneTechnique(self, attackID, oldDefense, newDefense):
        adversaries = aaDAO.getAllAdversaries()
        for adversary in adversaries:
            print(adversary['name'])
            print(list(tableCreator.adversaryTechniques.keys()))
            if adversary['name'] in list(tableCreator.adversaryTechniques.keys()):
                name = adversary['name']
                print(name)
                for technique in tableCreator.adversaryTechniques[name]:
                    if technique == attackID:
                        adversary['defense'] = tableCreator.adversaryTechniques[name] / (adversary['defense'] + newDefense - oldDefense)
                        aaDAO.updateAdversary(adversary)'''


    '''def updateAllAdversariesOneTechnique(self, attackID, oldDefense, newDefense):
        cursor = self.db.cursor()
        adversaries = self.getAllAdversariesByAttackID(attackID)
        for adversaryName in adversaries:
            sql = "update adversaries set defense = %s, residualRisk = %s where name = %s"
            adversary = self.findAdversaryByName(adversaryName)
            defense =  (adversary['defense'] + newDefense - oldDefense) / len(self.getAllAttackIDsByAdversaryName(adversaryName))
            residualRisk = adversary['inherentRisk'] - ((defense / 100) * adversary['inherentRisk'])
            values= [defense, residualRisk, adversaryName]
            cursor.execute(sql, values)
            self.db.commit()
        return'''



    def updateAllAdversariesOneTechnique(self, attackID, oldDefense, newDefense):
        cursor = self.db.cursor()
        adversaries = self.getAllAdversariesByAttackID(attackID)
        for adversaryName in adversaries:
            adversary = self.findAdversaryByName(adversaryName)
            if adversary:
                sql = "update adversaries set defense = %s, residualRisk = %s where name = %s"
                defense =  (adversary['defense'] + newDefense - oldDefense) / len(self.getAllAttackIDsByAdversaryName(adversaryName, "Actor"))
                residualRisk = adversary['inherentRisk'] - ((defense / 100) * adversary['inherentRisk'])
                values= [defense, residualRisk, adversaryName]
                cursor.execute(sql, values)
                self.db.commit()
            else:
                sql = "update malware set defense = %s, residualRisk = %s where name = %s"
                adversary = self.findMalwareByName(adversaryName)
                defense =  (adversary['defense'] + newDefense - oldDefense) / len(self.getAllAttackIDsByAdversaryName(adversaryName, "Malware"))
                residualRisk = adversary['inherentRisk'] - ((defense / 100) * adversary['inherentRisk'])
                values= [defense, residualRisk, adversaryName]
                cursor.execute(sql, values)
                self.db.commit()
        return



    '''def updateAdversariesAssessments(self):
        adversaries = self.getAllAdversaries()
        for adversary in adversaries:
            defensesList = []
            attackIDs = self.getAllAttackIDsByAdversaryName(adversary['name'])
            for attackID in attackIDs:
                defensesList.append(self.findByAttackID(attackID)['assessment'])
            try:
                adversary['defense'] = sum(defensesList) / len(defensesList)
                adversary['residualRisk'] = adversary['inherentRisk'] * adversary['defense'] / 100
                self.updateAdversary(adversary)
            except ZeroDivisionError:
                continue
        return'''


    def updateAdversariesAssessments(self):
        adversaries = self.getAllAdversaries()
        for adversary in adversaries:
            defensesList = []
            attackIDs = self.getAllAttackIDsByAdversaryName(adversary['name'], "Actor")
            for attackID in attackIDs:
                defensesList.append(self.findByAttackID(attackID)['assessment'])
            try:
                adversary['defense'] = sum(defensesList) / len(defensesList)
                adversary['residualRisk'] = adversary['inherentRisk'] * adversary['defense'] / 100
                self.updateAdversary(adversary)
            except ZeroDivisionError:
                continue
        return


    def updateMalwareAssessments(self):
        adversaries = self.getAllMalware()
        for adversary in adversaries:
            defensesList = []
            attackIDs = self.getAllAttackIDsByAdversaryName(adversary['name'], "Malware")
            for attackID in attackIDs:
                defensesList.append(self.findByAttackID(attackID)['assessment'])
            try:
                adversary['defense'] = sum(defensesList) / len(defensesList)
                adversary['residualRisk'] = adversary['inherentRisk'] * adversary['defense'] / 100
                self.updateMalware(adversary)
            except ZeroDivisionError:
                continue
        return



    # this takes a very long time to run, but updates all adversaries for all techniques
    # this is currently only run when the database is created,
    # but needs to be run then because we are using dummy data
    '''def updateAdversariesAssessments(self):
        adversaries = aaDAO.getAllAdversaries()
        for adversary in adversaries:
            if adversary['name'] in list(tableCreator.adversaryTechniques.keys()):
                name = adversary['name']
                all = self.getAllAttackPatterns()
                defenses = []
                defense = 0
                for technique in tableCreator.adversaryTechniques[name]:
                    for pattern in all:
                        if technique == pattern['attackID']:
                            defenses.append(pattern['assessment'])
                try:
                    defense = sum(defenses) / len(defenses)
                    adversary['defense'] = defense
                    aaDAO.updateAdversary(adversary)
                except ZeroDivisionError:
                    continue
                defense = sum(tableCreator.adversaryTechniques[name]) / len(tableCreator.adversaryTechniques[name])
                adversary['defense'] = defense
                aaDAO.updateAdversary(adversary)
    '''
        
    def delete(self, name):
        cursor = self.db.cursor()
        sql = "delete from tactics where attackID = %s"
        values = [name]
        cursor.execute(sql, values)
        sql = "delete from attackPatterns where attackID = %s"
        cursor.execute(sql, values)
        sql = "delete from adversaries where name = %s"
        cursor.execute(sql,values)
        sql = "delete from malware where name = %s"
        cursor.execute(sql,values)
        return {}
    

    def deleteAdversary(self, name):
        cursor = self.db.cursor()
        sql = "delete from adversaries where name = %s"
        values = [name]
        cursor.execute(sql, values)
        return {}


    def deleteMalware(self, name):
        cursor = self.db.cursor()
        sql = "delete from malware where name = %s"
        values = [name]
        cursor.execute(sql, values)
        return {}


    def convertTacticToDict(self, result):
        colnames = ['attackID', 'tacticName', 'description', 'assessment']
        tactic = {}
        if result:
            for i, colName in enumerate(colnames):
                value = result[i]
                tactic[colName] = value
            return tactic

    def convertPatternToDict(self, result):
        colnames = ['attackID', 'patternName', 'tacticName', 'isSubtechnique', 'hasSubtechnique', 'description', 'assessment']
        pattern = {}
        if result:
            for i, colName in enumerate(colnames):
                value = result[i]
                pattern[colName] = value
            return pattern
    

    def convertAdversaryToDict(self, result):
        colnames = ['name', 'description', 'inherentRisk', 'defense', 'residualRisk']
        adversary = {}
        if result:
            for i, colName in enumerate(colnames):
                value = result[i]
                adversary[colName] = value
            return adversary


aaDAO = AaDAO()