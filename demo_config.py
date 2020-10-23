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

args= get_args()
nae_password = "C@ndidadmin1234"
#Create NAE Object
nae = cnae.NAE (args.nae_ip)

#Log in to NAE with user and password
nae.login(args.user, nae_password,args.domain)
payload = ''' 
{
    "name": "Test2",
    "description": "",
    "event_rule_match_criteria": [
        {
            "event_name_match_criterion": {
                "value_equals": "EPG_HAS_NO_BD"
            },
            "affected_object_match_criteria": [
                {
                    "resource_type": "CANDID_OBJECT_TYPE_EPG",
                    "value_ends_with": "_mEPG"
                }
            ]
        }
    ],
    "suppression_action": "SUPPRESS",
    "next_step": ""
}
'''

r = nae.nae_rest("/nae/api/v1/event-services/assured-networks/2c0fc24b-d51ba4ba-d472-4bd1-ab19-b622bf4be892/event-management/event-rules",payload)
print(json.loads(r))