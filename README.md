# GMIT_data_representation_module

This repository contains the assessment tasks for the data representation module, namely:

1. AshleyCampionWeek1.xml, which is an xml representation of two books from a library.

2. MitreAttackAssessmentApp, which is a basic Flask application with a corresponding API.


## MitreAttackAssessmentApp

This Flask app is designed to allow an organization to track its defensive capacity against known cybersecurity attack-techniques tactics, actors, malware, and certain software tools, as well as track the risk that those actors, malware and tools present to their environment. It leverages the Mitre Att&ck framework to describe attack techniques and tactics, and pulls data from which Mitre Att&ck's TAXII server to determine which actors and malwares/tools are using which techniques.

For more information on the Mitre Att&ck framework, please visit [their website] (https://attack.mitre.org/). Details on how to interact programmatically with Mitre Att&ck's data can be found [here] (https://attack.mitre.org/resources/working-with-attack/). Mitre's data is structured in the STIX2 cyber threat intelligence data representation language, and can be leveraged using TAXII, which is standard for exchange of threat intelligence data in STIX. Information on TAXII can be found [here] (https://oasis-open.github.io/cti-documentation/taxii/intro.html) on STIX can be found [here] (https://github.com/oasis-open/cti-python-stix2).

## Directories / Files in MitreAttackAssessmentApp
* installRequirements.txt: a script to install the required Python packages
* loginManager.py: implements User class as various functions required to use flask's login-manager
* requirements.txt: the required packages listed
* runFirstTime.py: to run the app for the first time
* runNotFirstTime.py: for subsequent runs
* AttackAssessmentApp: the directory containing the app files, containing
> * dbFiles: a directory containing a config file and other files to create the database and tables, populate them using data pulled from Mitre's TAXII server, and interact with them (CRUD operations) using python.
> * static: directory containing the css and javascript files for the webpages
> * templates: directory containing the jinja2 templates for the webpages, i.e. the html files
> * \__init\__.py: which makes importing modules in and from the app easier
> forms.py: file defining the classes for login and registration forms
> * routes.py: file to tell the app what to do when a user navigates to a given directory of the webpage, i.e. this is the RESTful API of the app



## Version of Python Needed to Run this App
Python 3.7.4 was used to create the scripts in this repository (download it [here](https://www.python.org/downloads/)). Detailed instructions on how to download and install the latest version of Python are available [here](https://realpython.com/installing-python/). Any version of Python 3 can run the scripts. You can also download Python by downloading the Python distribution, Anaconda. You can download Anaconda [here](https://www.anaconda.com/distribution/), and you will find instructions on how to download and install Anaconda for Windows [here](https://docs.anaconda.com/anaconda/install/windows/).

## Database Software Required
The app uses a MYSQL database. Looking back, I should have used SQLAlchemy, as it is much easier to use SQLAlchemy with flask's login-manager package. MYSQL can be downloaded [here] (https://dev.mysql.com/downloads/installer/).


## Python Packages Required
The Python packages required to run the application can be found in requirements.txt. Howevever, there is a script, installRequirements.py, that will use PIP to install those packages for you, if you wish. The database for the app is MYSQL.


## How to Set Up the Application

1. Install Python3 (either directly or via the Anaconda distribution).

2. Install MYSQL.

3. Download this repository.

4. Run installRequirements.py to install the required Python packages. If this does not work, the packages required can be found in the requirements.txt file.

5. Create a config.py file in the AttackAssessmentApp\dbFiles directory, by adapting the configTemplate.py file in that same directory and using your own MYSQL username and password.

6. Run runFirstTime.py to run the application. It may take a number of minutes for the server to be spun up, as there are large number of tables that need to be created the first time the app is run. Data also has to pulled from the Mitre Att&ck server.

7. When the server is up and running, in your browser (preferably Chromium based), navigate to http://127.0.0.1:5000/ to use the application. You will first need to register with an email address (can be dummy) and password.

8. For subsequently runs of the application, run runNotFirstTime.py to avoid checking whether the database and tables need to created and populated again.


## How to Use the Application

Other than the login and registration pages, the app consists of five main pages:

1. Home: currently not displaying anything. This will allow the user to keep track of their high-priority actors and other custom data.

2. Tactics: displays a table of the tactics stored in the database.

3. Techniques: displays a table of the techniques in the database that belong to a given tactic / malware / actor. When accessing via the navigation bar, only tactic classification is possible

4. Adversaries: displays a table of the adversaries in the database, and allows one to navigate to the techniques page for the adversary.

5. Same as above but more malware / tools.

The main use for the app is the ability to enter a defence score for each technique (betweeen zero and one hundred, with onr hundred signifying a perfect defence). Aggregate defenses are then calculating for each tactic, adversary and malware/tool depending on the techniques they use/comprise. For adversaries and malware/tools, the user can enter an 'inherent risk' score (again, 0-100, but this time with 100 indicating the highest risk). The application then uses the defense value for the actor to calculate a residual risk score to reflect the true risk that actor or malware/tool presents to the organization.


## Incomplete Areas of the App

1. The home page has yet to be populated with content. This will in future provide a dashboard view of stats pertaining to threats etc. prioritized by the user.

2. Verification of legitimacy of email address, and ability to change email address, has not been implemented.

3. Techniques cannot be linked to actors / malware / tools that have not already been linked to them by Mitre Att&ck. This is obviously a critical use case that will be implemented in the future.
