import mysql.connector
from AttackAssessmentsApp.dbFiles import config as cfg
from AttackAssessmentsApp.dbFiles import createDB as createDB
from AttackAssessmentsApp.dbFiles.createTables import tableCreator as tableCreator

class AaDAO:
    db = ""
    def __init__(self):
        self.connectToDB()
    
        
    def connectToDB(self):
        self.db = mysql.connector.connect(
                host=cfg.ms['host'],
                user=cfg.ms['username'],
                pool_reset_session=False,
                password=cfg.ms['password'],
                database=cfg.ms['database'],
                pool_name = 'thePool',
                pool_size = 32
            )
        print("Connection made to AttackAssessment database.")
        
    def getCursor(self):
        if not self.db.is_connected():
            self.connectToDB()
        return self.db.cursor()

    def createUser(self, user, password):
        cursor = self.getCursor()
        sql = "insert into users (email, password) values (%s, %s)"
        values = [
            user,
            password
        ]
        cursor.execute(sql, values)
        self.db.commit()
        rwid = cursor.lastrowid
        cursor.close()
        return rwid
    # this method was resulting in MYSQL OperationalErrors
    # so I wrapped in try except and created new connections in except
    # solution only found when restarted MYSQL service
    def getUser(self, email):
        try:
            cursor = self.getCursor()
            sql = "select * from users where email = %s"
            values = [email]
            cursor.execute(sql, values)
            result = cursor.fetchall()
            cursor.close()
            return result
        except:
            self.db.close()
            self.connectToDB()
            cursor = self.getCursor()
            sql = "select * from users where email = %s"
            values = [email]
            cursor.execute(sql, values)
            result = cursor.fetchall()
            cursor.close()
            return result

    def createTactic(self, tactic):
        cursor = self.getCursor()
        sql = "insert into tactics (attackID, tacticName, description, assessment) values (%s, %s, %s, %s)"
        values = [
            tactic['attackID'],
            tactic['tacticName'],
            tactic['description'],
            tactic['assessment'],
        ]
        cursor.execute(sql, values)
        self.db.commit()
        rwid = cursor.lastrowid
        cursor.close()
        return rwid

    def createAttackPattern(self, pattern):
        cursor = self.getCursor()
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
        rwid = cursor.lastrowid    
        cursor.close()
        return rwid

    def createAdversary(self, adversary):
        cursor = self.getCursor()
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
        rwid = cursor.lastrowid
        cursor.close()
        return rwid

    def createMalware(self, malware):
        cursor = self.getCursor()
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
        rwid = cursor.lastrowid
        cursor.close()
        return rwid


    def createTechniquesOfAdversaryTable(self, user, type):
        cursor = self.getCursor()
        #backticks required for table-names with spaces
        sql = f"create table `{type}:{user}` (attackID varchar(30));"
        cursor.execute(sql)
        cursor.close()
        return

    def createTechniqueOfAdversary(self, user, attackID, type):
        cursor = self.getCursor()
        sql = f"insert into `{type}:{user}` (attackID) values ('{attackID}');"
        cursor.execute(sql)
        self.db.commit()
        rwid = cursor.lastrowid
        cursor.close()
        return rwid

    def createAdversaryUsingTechniqueTable(self, technique):
        cursor = self.getCursor()
        sql = f"create table `{technique}` (user varchar(30), type varchar(10));"
        cursor.execute(sql)
        cursor.close()
        return

    def createAdversaryUsingTechnique(self, technique, user, type):
        cursor = self.getCursor()
        sql = f"insert into `{technique}` (user, type) values ('{user}', '{type}');"
        cursor.execute(sql)
        self.db.commit()
        rwid = cursor.lastrowid
        cursor.close()
        return rwid


    def getAllTactics(self):
        cursor = self.getCursor()
        sql = "select * from tactics"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertTacticToDict(result)
            resultArray.append(resultAsDict)
        cursor.close()
        return resultArray

    def getAllAttackPatterns(self):
        cursor = self.getCursor()
        sql = "select * from attackPatterns"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertPatternToDict(result)
            resultArray.append(resultAsDict)
        cursor.close()
        return resultArray

    def getAllAdversaries(self):
        cursor = self.getCursor()
        sql = "select * from adversaries"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertAdversaryToDict(result)
            resultArray.append(resultAsDict)
        cursor.close()
        return resultArray


    def getAllMalware(self):
        cursor = self.getCursor()
        sql = "select * from malware"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for result in results:
            resultAsDict = self.convertAdversaryToDict(result)
            resultArray.append(resultAsDict)
        cursor.close()
        return resultArray


    def getAllAdversariesByAttackID(self, attackID):
        cursor = self.getCursor()
        sql = f"select adversary from `{attackID}`"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for i in results:
            resultArray.append(i[0])
        cursor.close()
        return resultArray
    

    def getAllAttackIDsByAdversaryName(self, user, type):
        cursor = self.getCursor()
        sql = f"select attackID from `{type}:{user}`"
        cursor.execute(sql)
        results = cursor.fetchall()
        resultArray = []
        for i in results:
            resultArray.append(i[0])
        cursor.close()
        return resultArray

    def findAdversaryByName(self, name):
        cursor = self.getCursor()
        sql = "select * from adversaries where name = %s"
        values = [name]
        cursor.execute(sql, values)
        result = cursor.fetchone()
        if result:
            return self.convertAdversaryToDict(result)



    def findMalwareByName(self, name):
        cursor = self.getCursor()
        sql = "select * from malware where name = %s"
        values = [name]
        cursor.execute(sql, values)
        result = cursor.fetchone()
        cursor.close()
        if result:
            return self.convertAdversaryToDict(result)


    def findByAttackID(self, attackID):
        cursor = self.getCursor()
        if attackID[:2] == "TA":
            sql = "select * from tactics where AttackID = %s"
            values = [attackID]
            cursor.execute(sql, values)
            result = cursor.fetchone()
            cursor.close()
            if result:
                return self.convertTacticToDict(result)
        else:
            sql = "select * from attackPatterns where AttackID = %s"
            values = [attackID]
            cursor.execute(sql, values)
            result = cursor.fetchone()
            cursor.close()
            if result:
                return self.convertPatternToDict(result)
        
    
    
    def updateTactic(self, tactic):
        cursor = self.getCursor()
        sql = "update tactics set tacticName = %s, description = %s, assessment = %s where attackID = %s"
        values = [
            tactic['tacticName'],
            tactic['description'],
            tactic['assessment'],
            tactic['attackID']
        ]
        cursor.execute(sql, values)
        self.db.commit()
        cursor.close()
        return tactic

    def updateAttackPattern(self, pattern):
        cursor = self.getCursor()
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
        cursor.close()
        return pattern

    def updateAdversary(self, adversary):
        cursor = self.getCursor()
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
        cursor.close()
        return adversary



    def updateMalware(self, malware):
        cursor = self.getCursor()
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
        cursor.close()
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



    def updateAllAdversariesOneTechnique(self, attackID, oldDefense, newDefense):
        cursor = self.getCursor()
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
        cursor.close()
        return


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

        
    def delete(self, name):
        cursor = self.getCursor()
        sql = "delete from tactics where attackID = %s"
        values = [name]
        cursor.execute(sql, values)
        sql = "delete from attackPatterns where attackID = %s"
        cursor.execute(sql, values)
        sql = "delete from adversaries where name = %s"
        cursor.execute(sql,values)
        sql = "delete from malware where name = %s"
        cursor.execute(sql,values)
        cursor.close()
        return {}
    

    def deleteAdversary(self, name):
        cursor = self.getCursor()
        sql = "delete from adversaries where name = %s"
        values = [name]
        cursor.execute(sql, values)
        cursor.close()
        return {}


    def deleteMalware(self, name):
        cursor = self.getCursor()
        sql = "delete from malware where name = %s"
        values = [name]
        cursor.execute(sql, values)
        cursor.close()
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