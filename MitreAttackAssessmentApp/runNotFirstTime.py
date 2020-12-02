from AttackAssessmentsApp import app
from AttackAssessmentsApp.dbFiles import createDB
from AttackAssessmentsApp.dbFiles.createTables import tableCreator


if __name__ == "__main__":
    app.run(debug=True)