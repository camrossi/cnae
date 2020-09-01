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


# Create PCV


changes ='''[
{

"fvTenant": {
        "attributes": {
          "descr": "",
          "nameAlias": "",
          "userdom": "all",
          "dn": "uni/tn-I_ROCK",
          "name": "123",
          "pcv_status": "created"
        },
        "children": []
      }
    },
    {
      "fvTenant": {
        "attributes": {
          "descr": "",
          "nameAlias": "",
          "userdom": "all",
          "dn": "uni/tn-I_ROCK_MUCH",
          "name": "456",
          "pcv_status": "created"
        },
        "children": []
      }
    },
    {
      "physDomP": {
        "attributes": {
          "dn": "uni/phys-NAE-pdom",
          "name": "NAE-pdom",
          "nameAlias": "",
          "ownerKey": "",
          "ownerTag": "",
          "userdom": ""
        }
      }
    },
    {
      "infraInfra": {
        "attributes": {
          "childAction": "",
          "dn": "uni/infra"
        },
        "children": [
          {
            "infraAttEntityP": {
              "attributes": {
                "annotation": "orchestrator:aci-containers-controller",
                "descr": "",
                "dn": "uni/infra/attentp-NAE_AEP",
                "name": "NAE_AEP",
                "nameAlias": "",
                "ownerKey": "",
                "ownerTag": "",
                "userdom": ""
              }
            }
          }
        ]
      }

}
]'''


nae.newManualPCV(changes = changes,ag_name="Pre Change Verification",name="TestSuper", description="dCloud Demo")
