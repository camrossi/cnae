# This script will pre-configure a NAE appliance for some demo time.
# I expect the appliance to be with no config, if an object already exist I will not update it, the object creation will just fail and I move on. 
# To do: Move the configuration snippet outside of this file.
import cnae
import logging
import time
import argparse
import getpass
from pprint import pprint


# Enble logging at debug level
logger = logging.getLogger('cnae')
logger.setLevel(logging.INFO)

def get_args():
    parser = argparse.ArgumentParser(description="Prepare an NAE appliace for Demo Time!")
    parser.add_argument('-u', dest='user', help='Username, default: admin', default='admin')
    parser.add_argument('-d', dest='domain', help='Login Domain, defaul: Local',default='Local')
    parser.add_argument('-i', dest='nae_ip', help='IP address of the NAE Appliance',required=True)
    args = parser.parse_args()
    return args

def deltaAnalysis(ag_name):
    epochs = nae.getEpochs(ag_name)
    epochs_id = []
    # Do a delta analysis only if there are 2+ epochs 
    if len(epochs) >= 2:
       for e in epochs:
           epochs_id.append(e['epoch_id'])
       
       #pair the epochs together and drop the last pair, I do not need newest-oldest epoch pair. 
       #This creates one delta analysis between every epoch
       epoch_pairs = (list(zip(epochs_id, epochs_id[1:] + epochs_id[:1])))
       epoch_pairs.pop()
       
       #Start epoch delta
       i = 1
       for e in epoch_pairs:
           name = ag_name+ '_' + str(i)
           nae.newDelataAnalysis(name, prior_epoch_uuid=e[0], later_epoch_uuid=e[1])
           i = i + 1


args= get_args()
nae_password = getpass.getpass()
#Create NAE Object
nae = cnae.NAE (args.nae_ip)

#Log in to NAE with user and password
nae.login(args.user, nae_password,args.domain)

#Create assurange Groups
nae.newOfflineAG("Change Management")
nae.newOfflineAG("Data Center Operations")
nae.newOfflineAG("Migration")
nae.newOfflineAG("Epoch Analysis")
nae.newOfflineAG("Segmentation Compliance")
nae.newOfflineAG("Config Compliance")




object_selectors=[
                  '''{
                        "name": "DataBase",
                    "description": null,
                    "includes": [
                      {
                        "matches": [
                          {
                            "application_epgmatch": {
                              "object_attribute": "DN",
                              "tenant": {
                                "pattern": "NAE_Compliance",
                                "type": "EXACT"
                              },
                              "application_profile": {
                                "pattern": "ComplianceIsGood",
                                "type": "EXACT"
                              },
                              "application_epg": {
                                "pattern": "DataBase",
                                "type": "EXACT"
                              }
                            }
                          }
                        ]
                      }
                    ],
                    "excludes": [],
                    "selector_type": "OST_EPG"
                  }''',
                  '''{
                    "name": "FrontEnd",
                    "description": null,
                    "includes": [
                      {
                        "matches": [
                          {
                            "application_epgmatch": {
                              "object_attribute": "DN",
                              "tenant": {
                                "pattern": "NAE_Compliance",
                                "type": "EXACT"
                              },
                              "application_profile": {
                                "pattern": "ComplianceIsGood",
                                "type": "EXACT"
                              },
                              "application_epg": {
                                "pattern": "FrontEnd",
                                "type": "EXACT"
                              }
                            }
                          }
                        ]
                      }
                    ],
                    "excludes": [],
                    "selector_type": "OST_EPG"
                  }''','''
                  {
                    "name": "BDs In Common",
                    "description": null,
                    "includes": [
                      {
                        "matches": [
                          {
                            "tenant_match": {
                              "object_attribute": "DN",
                              "tenant": {
                                "pattern": "common",
                                "type": "CONTAINS"
                              }
                            }
                          }
                        ]
                      }
                    ],
                    "excludes": [],
                    "selector_type": "OST_BD"
                  }'''
                  ]
for obj in object_selectors:
    nae.newObjectSelector(obj)


compliance_requirements = [
'''
                            {
                                  "name": "Segmentation",
                                  "config_compliance_parameter": {
                                    "and_list_list": [],
                                    "or_list_list": []
                                  },
                                  "epgselector_a": "FrontEnd",
                                  "epgselector_b": "DataBase",
                                  "requirementType": "SEGMENTATION",
                                  "communicationType": "MUST_NOT",
                                  "isAllTraffic": false
                            }''','''
                            {
                              "name": "BD Config Requirement",
                              "requirementType": "CONFIGURATION_COMPLIANCE",
                              "epgselector_a": "BDs In Common",
                              "config_compliance_parameter": {
                                "and_list_list": [
                                  {
                                    "parameter": "CCP_L2_UNKNOWN_UNICAST",
                                    "string_value": "Hardware Proxy",
                                    "operator": "EQUAL_TO"
                                  },
                                  {
                                    "parameter": "CCP_LIMIT_IP_LEARNING_TO_SUBNET",
                                    "string_value": "Yes",
                                    "operator": "EQUAL_TO"
                                  }
                                ]
                              }
                            }'''
                                ]

for obj in compliance_requirements:
    nae.newComplianceRequirement(obj)

sseg = nae.getAG('Segmentation Compliance')
cseg = nae.getAG('Config Compliance')

requirement_sets = [
                     '''{
                        "assurance_groups": [
                            {
                                "active": true,
                                "fabric_uuid": "''' + sseg['uuid'] + '''"

                            }
                        ],
                        "name": "Segmentation Compliance",
                        "requirements": [
                            "Segmentation"
                        ]
                    }''','''
                    {
                      "name": "BD Config Compliance",
                      "requirements": [
                        "BD Config Requirement"
                      ],
                      "assurance_groups": [
                        {
                         "active": true,
                         "fabric_uuid": "''' + cseg['uuid'] + '''"
                          
                        }
                      ],
                      "description": null
                    }'''
                   ]

for obj in requirement_sets:
    nae.newComplianceRequirementSet(obj)


offline_analysis = [{"ag":"Segmentation Compliance", "filename": ["Segmentation_Epoch1.tar.gz", "Segmentation_Epoch2.tar.gz", "Segmentation_Epoch3.tar.gz" ]},
                    {"ag":"Config Compliance", "filename": ["Config Compliance.gz"]},
                    {"ag":"Change Management", "filename": ["ChangeMgmt.tar.gz"]},
                    {"ag":"Data Center Operations", "filename": ["DCOperations.tar.gz"]},
                    {"ag":"Epoch Analysis", "filename": ["EpochDelta.tar.gz"]},
                    {"ag":"Migration", "filename": ["Migrations.tar.gz"]}
                    ]
#Load the list of Offline dataset
nae.getFiles()

#for all the assurance group 
for ag in offline_analysis:
    #Get the fabricID
    fabricID = str(nae.getAG(ag['ag'])['uuid'])
    #for all the files in the assurange group list
    for f in ag['filename']:
        #genarate the name from the file (remving the extension)
        offline_analysis_name = f.split('.')[0]
        # Get the file ID from the file name
        fileID = str(next(item for item in nae.files if item["filename"] == f)['uuid'])
        #Start a new Offline Analysis
        nae.newOfflineAnalysis(offline_analysis_name, fileID, fabricID)

# Create Delta Analysis:
for ag in  offline_analysis:
    deltaAnalysis(str(nae.getAG(ag['ag'])['unique_name']))
