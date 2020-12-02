/* Pipe to mysql.exe or copy into mysql command line.
'createNewDb.py' should be run to create the database and tables. 
Note that this script will not populate the tables with data from Mitre Attack.
It also does not account for all the tables used by this app.
To populate the tables with data from Mitre Attack, please run 'createNewDb.py'.
This is just intended for reference. */

create database AttackAssessment;
use AttackAssessment;

create table tactics(
attackID varchar(15) PRIMARY KEY,
tacticName varchar(50),
description varchar(2000),
assessment int
);

create table attackPatterns(
attackID varchar(20) PRIMARY KEY,
patternName varchar(100),
tacticName varchar(50),
isSubtechnique boolean,
hasSubtechnique boolean,
description varchar(2000),
assessment int
);

create table adversaries(
name varchar(30) PRIMARY KEY,
description varchar(2000),
inherentRisk int,
defense int,
residualRisk int
);



