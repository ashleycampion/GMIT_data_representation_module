# Comment out lines 10 and 11 if database and tables
# do not need to be created.

from AttackAssessmentsApp.dbFiles import createDB
from AttackAssessmentsApp.dbFiles.createTables import tableCreator
from AttackAssessmentsApp import app

if __name__ == "__main__":
    tableCreator.createMainTables()
    app.run(debug=True)