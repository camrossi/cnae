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
           nae.newDeltaAnalysis(name, prior_epoch_uuid=e[0], later_epoch_uuid=e[1])
           i = i + 1


args= get_args()
nae_password = "C@ndidadmin1234"
#nae_password = getpass.getpass()
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
nae.newOfflineAG("Pre Change Verification")
nae.newOfflineAG("Fab5")

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
                  }''','''{
                        "name": "WebService",
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
                                "pattern": "WebService",
                                "type": "EXACT"
                              }
                            }
                          }
                        ]
                      }
                    ],
                    "excludes": [],
                    "selector_type": "OST_EPG"
                  }''','''{
                        "name": "PreProdDB",
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
                                "pattern": "PreProdDB",
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
                                  "config_compliance_parameter": {},
                                  "epg_selector_a": "FrontEnd",
                                  "epg_selector_b": "DataBase",
                                  "requirement_type": "SEGMENTATION",
                                  "communication_type": "MUST_NOT",
                                  "enable_aggregate_event_for_tenant": false,
                                  "is_all_traffic": false
                            }''','''
                            {
                              "name": "BD Config Requirement",
                              "requirement_type": "CONFIGURATION_COMPLIANCE",
                              "epg_selector_a": "BDs In Common",
                              "config_compliance_parameter": {
                                "and_parameters": [
                                  {
                                    "parameter": "CCP_L2_UNKNOWN_UNICAST",
                                    "value": "Hardware Proxy",
                                    "operator": "EQUAL_TO"
                                  },
                                  {
                                    "parameter": "CCP_LIMIT_IP_LEARNING_TO_SUBNET",
                                    "value": "Yes",
                                    "operator": "EQUAL_TO"
                                  }
                                ]
                              }
                            }''','''{
                                  "name": "PCV Segmentation",
                                  "config_compliance_parameter": {                                  },
                                  "epg_selector_a": "WebService",
                                  "epg_selector_b": "PreProdDB",
                                  "requirement_type": "SEGMENTATION",
                                  "communication_type": "MUST_NOT",
                                  "is_all_traffic": false
                            }''' 
                                ]

for obj in compliance_requirements:
    nae.newComplianceRequirement(obj)

sseg = nae.getAG('Segmentation Compliance')
cseg = nae.getAG('Config Compliance')
pcvseg = nae.getAG('Pre Change Verification')


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
                    }''','''
                    {
                      "name": "PCV Compliance",
                      "requirements": [
                        "PCV Segmentation"
                      ],
                      "assurance_groups": [
                        {
                         "active": true,
                         "fabric_uuid": "''' + pcvseg['uuid'] + '''"
                          
                        }
                      ],
                      "description": null
                    }'''

                   ]

for obj in requirement_sets:
    nae.newComplianceRequirementSet(obj)

offline_analysis = [{"ag":"Segmentation Compliance", "filename": ["Segmentation_Epoch1.tar.gz", "Segmentation_Epoch2.tar.gz", "Segmentation_Epoch3.tar.gz" ]},
                    {"ag":"Config Compliance", "filename": ["Config_Compliance.tar.gz"]},
                    {"ag":"Change Management", "filename": ["ChangeMgmt.tar.gz"]},
                    {"ag":"Data Center Operations", "filename": ["DCOperations.tar.gz"]},
                    {"ag":"Epoch Analysis", "filename": ["EpochDelta.tar.gz"]},
                    {"ag":"Fab5", "filename": ["Can5_mod28_withAuditLog.tar.gz"]},
                    {"ag":"Pre Change Verification", "filename": ["Pre Change Verification.tar.gz"]},
                    {"ag":"Migration", "filename": ["Migrations.tar.gz"]}
                    ]

#can be any existing AG
ag_uuid  = nae.getAG('Segmentation Compliance')


for oa in offline_analysis:
    for f in oa["filename"]:
        unique_name = f.strip().split("/")[-1]

        #I get the major version of NAE and expect the files to be in the right folder 4.1 for NAE 4.1.x and 5.0 for NAE 5.0.x
        nae.upload_file(unique_name, "./" + nae.version[0:3]+ "/" + f, fabric_uuid=ag_uuid)
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

# Create PCV


changes ='''[{
      "fvBD": {
        "attributes": {
          "OptimizeWanBandwidth": "no",
          "arpFlood": "no",
          "descr": "",
          "epClear": "no",
          "hostBasedRouting": "no",
          "intersiteBumTrafficAllow": "no",
          "intersiteL2Stretch": "no",
          "ipLearning": "yes",
          "limitIpLearnToSubnets": "yes",
          "llAddr": "",
          "mac": "00:22:BD:F8:19:FF",
          "mcastAllow": "no",
          "multiDstPktAct": "bd-flood",
          "nameAlias": "",
          "type": "regular",
          "unicastRoute": "yes",
          "unkMacUcastAct": "proxy",
          "unkMcastAct": "flood",
          "v6unkMcastAct": "flood",
          "vmac": "not-applicable",
          "dn": "uni/tn-NAE_Compliance/BD-BD2",
          "name": "BD2",
          "pcv_status": "created"
        },
        "children": [
          {
            "fvRsCtx": {
              "attributes": {
                "tnFvCtxName": "VRF1",
                "pcv_status": "created"
              }
            }
          }
        ]
      }
    },
    {
      "fvSubnet": {
        "attributes": {
          "ctrl": "nd",
          "descr": "",
          "name": "",
          "nameAlias": "",
          "preferred": "no",
          "scope": "private",
          "virtual": "no",
          "dn": "uni/tn-NAE_Compliance/BD-BD2/subnet-192.168.1.1/16",
          "ip": "192.168.1.1/16",
          "pcv_status": "created"
        },
        "children": []
      }
    },
    {
      "fvAEPg": {
        "attributes": {
          "descr": "",
          "exceptionTag": "",
          "floodOnEncap": "disabled",
          "fwdCtrl": "none",
          "hasMcastSource": "no",
          "isAttrBasedEPg": "no",
          "matchT": "AtleastOne",
          "nameAlias": "",
          "pcEnfPref": "unenforced",
          "prefGrMemb": "exclude",
          "prio": "unspecified",
          "shutdown": "no",
          "dn": "uni/tn-NAE_Compliance/ap-ComplianceIsGood/epg-PreProdDB",
          "name": "PreProdDB",
          "pcv_status": "created"
        },
        "children": [
          {
            "fvRsBd": {
              "attributes": {
                "tnFvBDName": "BD2",
                "pcv_status": "created"
              }
            }
          },
          {
            "fvRsCons": {
              "attributes": {
                "tnVzBrCPName": "Web_DB",
                "pcv_status": "created"
              }
            }
          }
        ]
      }
    }
]'''


nae.newManualPCV(changes = changes,ag_name="Pre Change Verification",name="Add_BD_EPG_NotOK", description="dCloud Demo")
