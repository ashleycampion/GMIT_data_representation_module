# Warning! Running this file may replace any tables
# previously created for this app. Ensure lines 56-59 
# are commented out to prevent replacement of tables
# if they already exist.

import mysql.connector
from AttackAssessmentsApp.dbFiles import config as cfg


#https://github.com/mitre/cti/blob/master/USAGE.md

from stix2 import TAXIICollectionSource
from stix2 import MemoryStore, Filter
from taxii2client.v20 import Collection # only specify v20 if your installed version is >= 2.0.0

import AttackAssessmentsApp.dbFiles.AaDAO as AaDAO
import numpy
from itertools import chain
import requests

collections = {
    "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
    "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b",
    "ics-attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
}

collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections['enterprise_attack']}/")
src = TAXIICollectionSource(collection)


def get_software(thesrc):
    return list(chain.from_iterable(
        thesrc.query(f) for f in [
            Filter("type", "=", "tool"), 
            Filter("type", "=", "malware")
        ]
    ))

def get_data_from_branch(domain, branch="master"):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])



def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """

    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False)
    ])

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {} 

    # build the dict
    for relationship in relationships:
        if (src_type in relationship.source_ref and target_type in relationship.target_ref):
            if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse: 
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else: 
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship, 
                        "id": relationship.source_ref
                    })
            else: 
                # create a new entry
                if not reverse: 
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship, 
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship, 
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output


# software:group
def software_used_by_groups(thesrc):
    """returns group_id => {software, relationship} for each software used by the group."""
    return get_related(thesrc, "intrusion-set", "uses", "tool") + get_related(thesrc, "intrusion-set", "uses", "malware")

def groups_using_software(thesrc):
    """returns software_id => {group, relationship} for each group using the software."""
    return get_related(thesrc, "intrusion-set", "uses", "tool", reverse=True) + get_related(thesrc, "intrusion-set", "uses", "malware", reverse=True)

# technique:group
def techniques_used_by_groups(thesrc):
    """returns group_id => {technique, relationship} for each technique used by the group."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern")

def groups_using_technique(thesrc):
    """returns technique_id => {group, relationship} for each group using the technique."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern", reverse=True)

# technique:software
def techniques_used_by_software(thesrc):
    """return software_id => {technique, relationship} for each technique used by the software."""
    result = get_related(thesrc, "tool", "uses", "attack-pattern")
    result.update(get_related(thesrc, "malware", "uses", "attack-pattern"))
    return result

def software_using_technique(thesrc):
    """return technique_id  => {software, relationship} for each software using the technique."""
    result = get_related(thesrc, "tool", "uses", "attack-pattern", reverse=True)
    result.update(get_related(thesrc, "malware", "uses", "attack-pattern", reverse=True))
    return result


# technique:mitigation
def mitigation_mitigates_techniques(thesrc):
    """return mitigation_id => {technique, relationship} for each technique mitigated by the mitigation."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=False)

def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)

# technique:subtechnique
def subtechniques_of(thesrc):
    """return technique_id => {subtechnique, relationship} for each subtechnique of the technique."""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True)

def parent_technique_of(thesrc):
    """return subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique"""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern")[0]













class TableCreator:
    
    def __init__(self):
        self.adversaryTechniques = {}
        self.thesrc = get_data_from_branch("enterprise-attack")
        return


    def createMainTables(self):
        db = mysql.connector.connect(
        host=cfg.ms['host'],
        user=cfg.ms['username'],
        password=cfg.ms['password'],
        database=cfg.ms['database']
    )

        
        cursor = db.cursor()
        #sql = "create database AttackAssessment;"
        #cursor.execute(sql)

        sql = "use AttackAssessment;"
        cursor.execute(sql)

        #uncomment next four lines to create new tables if already exist
        #cursor.execute("drop table tactics;")
        #print("Table 'tactics' deleted.")
        #cursor.execute("drop table attackpatterns;")
        #print("Table 'attackPatterns' deleted.")
        #cursor.execute("drop table adversaries;")
        #print("Table 'adversaries' deleted.")
        #cursor.execute("drop table malware;")
        #print("Table 'malware' deleted.")
        #cursor.execute("drop table users;")
        #print("Table 'users' deleted.")

        cursor.execute("show tables;")
        tables=[]
        for cursors in cursor:
            tables.append(cursors)
        tables = list(zip(*tables)) 


        if len(tables) > 0:
            if "attackpatterns" not in tables[0]:
                print("Creating table 'attackPatterns'... ")
                sql = "create table attackPatterns(attackID varchar(20) PRIMARY KEY, patternName varchar(100), tacticName varchar(50), isSubtechnique boolean, hasSubtechnique boolean, description varchar(5000), assessment int);"
                cursor.execute(sql)
                self.populateAttackPatternsTable()
                print("Table 'attackPatterns' created and populated successfully.")
            else:
                print("Table 'attackPatterns' already exists. Comment out the appropriate lines around 210-218 to have this table replaced.")
            
            if "tactics" not in tables[0]:
                print("Creating table 'tactics'... ")
                sql = "create table tactics(attackID varchar(15) PRIMARY KEY, tacticName varchar(50), description varchar(5000), assessment int);"
                cursor.execute(sql)
                self.populateTacticsTable()
                print("Table 'tactics' created and populated successfully.")
            else:
                print("Table 'tactics' already exists. Comment out the appropriate lines around 210-218 to have this table replaced.")
            
            if "adversaries" not in tables[0]:
                print("Creating table 'adversaries'...")
                sql = "create table adversaries(name varchar(32) PRIMARY KEY, description varchar(2000), inherentRisk int, defense int, residualRisk int);"
                cursor.execute(sql)
                self.populateAdversariesTable()
                print("Table 'adversaries' created and populated successfully.")
            else:
                print("Table 'adversaries' already exists. Comment out the appropriate lines around 210-218 to have this table replaced.")
            
            if "malware" not in tables[0]:
                print("Creating table 'malware'...")
                sql = "create table malware(name varchar(32) PRIMARY KEY, description varchar(2000), inherentRisk int, defense int, residualRisk int);"
                cursor.execute(sql)
                self.populateMalwareTable()
                print("Table 'malware' created and populated successfully.")
            else:
                print("Table 'malware' already exists. Comment out the appropriate lines around 210-218 to have this table replaced.")

            if "users" not in tables[0]:
                print("Creating table 'users'...")
                sql = "create table users(email varchar(32) PRIMARY KEY, password varchar(300));"
                cursor.execute(sql)
                print("Table 'users' created and populated successfully.")
            else:
                print("Table 'users' already exists. Comment out the appropriate lines around 210-218 to have this table replaced.")


        if len(tables) == 0:
            print("Creating table 'attackPatterns'... ")
            sql = "create table attackPatterns(attackID varchar(20) PRIMARY KEY, patternName varchar(100), tacticName varchar(50), isSubtechnique boolean, hasSubtechnique boolean, description varchar(2000), assessment int);"
            cursor.execute(sql)
            self.populateAttackPatternsTable()
            print("Table 'attackPatterns' created and populated successfully.")

            print("Creating table 'tactics'... ")
            sql = "create table tactics(attackID varchar(15) PRIMARY KEY, tacticName varchar(50), description varchar(1000), assessment int);"
            cursor.execute(sql)
            self.populateTacticsTable()
            print("Table 'tactics' created and populated successfully.")

            
            print("Creating table 'adversaries'...")
            sql = "create table adversaries(name varchar(32) PRIMARY KEY, description varchar(2000), inherentRisk int, defense int, residualRisk int);"
            cursor.execute(sql)
            self.populateAdversariesTable()
            print("Table 'adversaries' created and populated successfully.")


            print("Creating table 'malware'...")
            sql = "create table malware(name varchar(32) PRIMARY KEY, description varchar(2000), inherentRisk int, defense int, residualRisk int);"
            cursor.execute(sql)
            self.populateMalwareTable()
            print("Table 'malware' created and populated successfully.")

            print("Creating table 'users'...")
            sql = "create table users(email varchar(32) PRIMARY KEY, password varchar(300));"
            cursor.execute(sql)
            print("Table 'users' created and populated successfully.")
            print("All tables created and populated successfully.")



    def populateTacticsTable(self):
        groups = src.query([ Filter("type", "=", "x-mitre-tactic") ])
        for i in groups:
            tactic = {}
            attackID = i["external_references"][0]["external_id"]
            tactic["attackID"] = attackID
            tacticName = i["name"]
            tactic["tacticName"] = tacticName
            description = i["description"].split(". ")[0]
            tactic["description"] = description
            assessment = 0
            tactic["assessment"] = assessment
            AaDAO.aaDAO.createTactic(tactic)
        AaDAO.aaDAO.updateTacticsAssessments()


    def populateAttackPatternsTable(self):
        groups = src.query([ Filter("type", "=", "attack-pattern") ])
        for i in groups:
            try:
                pattern = {}
                attackID = i["external_references"][0]["external_id"]
                pattern["attackID"] = attackID
                patternName = i["name"]
                pattern["patternName"] = patternName
                tacticName = i["kill_chain_phases"][0]["phase_name"]
                pattern["tacticName"] = tacticName
                isSubtechnique = i["x_mitre_is_subtechnique"]
                pattern["isSubtechnique"] = isSubtechnique
                hasSubtechnique = False
                pattern["hasSubtechnique"] = hasSubtechnique
                description = i["description"].split(". ")[0]
                pattern["description"] = description
                assessment = numpy.random.randint(0,100)
                pattern["assessment"] = assessment
                AaDAO.aaDAO.createAttackPattern(pattern)
            except KeyError:
                continue



    def populateAdversariesTable(self):
        print("Creating tables to link adversaries to techniques... this may take some time... ")
        relationships = techniques_used_by_groups(self.thesrc)
        groups = src.query([ Filter("type", "=", "intrusion-set") ])
        for group in groups:
            try:
                adversary = {}
                name = group['name']
                adversary['name'] = name
                description = name + group['description'].split(")")[1].split(". ")[0]
                adversary['description'] = description
                id = group['id']
                #self.adversaryTechniques[name] = []
                AaDAO.aaDAO.createTechniquesOfAdversaryTable(name, "Actor")
                for i in relationships[id]:
                    #self.adversaryTechniques[name].append(i['object']["external_references"][0]["external_id"])
                    AaDAO.aaDAO.createTechniqueOfAdversary(name, i['object']["external_references"][0]["external_id"], "Actor")
            except KeyError:
                continue
            except IndexError:
                continue
            adversary['inherentRisk'] = numpy.random.randint(0,100)
            adversary['defense'] = 0
            adversary['residualRisk'] = 0
            AaDAO.aaDAO.createAdversary(adversary)
        AaDAO.aaDAO.updateAdversariesAssessments()
        self.populateTechniqueAdversariesTables()

        
        
    def populateTechniqueAdversariesTables(self):
        relationships = groups_using_technique(self.thesrc)
        techniques = src.query([ Filter("type", "=", "attack-pattern") ])
        for technique in techniques:
            try:
                name = technique["external_references"][0]["external_id"]
                id = technique['id']
                #print(id)
                #print(f'name is {name}')
                #print(relationships[id][0]['object']['name'])
                AaDAO.aaDAO.createAdversaryUsingTechniqueTable(name)
                for i in relationships[id]:
                    AaDAO.aaDAO.createAdversaryUsingTechnique(name, i['object']['name'], "actor")
            except KeyError:
                continue
            except IndexError:
                continue



    def populateTechniqueMalwareTables(self):
        relationships = software_using_technique(self.thesrc)
        techniques = src.query([ Filter("type", "=", "attack-pattern") ])
        for technique in techniques:
            try:
                name = technique["external_references"][0]["external_id"]
                id = technique['id']
                #print(id)
                #print(f'name is {name}')
                #print(relationships[id][0]['object']['name'])
                for i in relationships[id]:
                    AaDAO.aaDAO.createAdversaryUsingTechnique(name, i['object']['name'], "malware")
            except KeyError:
                continue
            except IndexError:
                continue


    def populateMalwareTable(self):
        print("Creating tables to link malwares to techniques... this may take some time... ")
        relationships = techniques_used_by_software(self.thesrc)
        softwares = get_software(self.thesrc)
        for software in softwares:
            try:
                adversary = {}
                name = software['name']
                adversary['name'] = name
                description = name + software['description'].split(")")[1].split(". ")[0]
                adversary['description'] = description
                id = software['id']
                #self.adversaryTechniques[name] = []
                AaDAO.aaDAO.createTechniquesOfAdversaryTable(name, "Malware")
                for i in relationships[id]:
                    #self.adversaryTechniques[name].append(i['object']["external_references"][0]["external_id"])
                    AaDAO.aaDAO.createTechniqueOfAdversary(name, i['object']["external_references"][0]["external_id"], "Malware")
            except KeyError:
                continue
            except IndexError:
                continue
            adversary['inherentRisk'] = numpy.random.randint(0,100)
            adversary['defense'] = 0
            adversary['residualRisk'] = 0
            AaDAO.aaDAO.createMalware(adversary)
        AaDAO.aaDAO.updateMalwareAssessments()
        self.populateTechniqueMalwareTables()



tableCreator = TableCreator()














if __name__ == "__main__":
    tableCreator.createMainTables()