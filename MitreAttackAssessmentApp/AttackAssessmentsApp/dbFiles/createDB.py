# Warning! Running this file may replace any tables
# previously created for this app.

import mysql.connector
from AttackAssessmentsApp.dbFiles import config as cfg

class CreateDb:

    def __init__(self):
        db = mysql.connector.connect(
                host=cfg.ms['host'],
                user=cfg.ms['username'],
                password=cfg.ms['password'],
            )
        cursor = db.cursor(buffered=True)
        cursor.execute("show databases")
        databases=[]
        for cursors in cursor:
            databases.append(cursors)
        databases = list(zip(*databases)) 
        if len(databases) > 0  and "attackassessment" in databases[0]:
            db = mysql.connector.connect(
                host=cfg.ms['host'],
                user=cfg.ms['username'],
                password=cfg.ms['password'],
                database=cfg.ms['database']
            )
        else:
            cursor.execute("create database AttackAssessment;")
            print("Database 'AttackAssessment' has been created.")


CreateDb = CreateDb()