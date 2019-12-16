# Example Script on how to usee getTcamStats
import cnae
import time
import argparse
import getpass
import json
from datetime import datetime
import logging

logger = logging.getLogger('cnae')
logger.setLevel(logging.DEBUG)


def get_args():
    parser = argparse.ArgumentParser(description="Script to dump all the TCAM stats to a json file")
    parser.add_argument('-u', dest='user', help='Username, default: admin', default='admin')
    parser.add_argument('-i', dest='nae_ip', help='IP address of the NAE Appliance',required=True)
    parser.add_argument('-d', dest='domain', help='Login Domain, defaul: Local',default='Local')
    parser.add_argument('-a', dest='ag_name', help='Assurance Group Name', required=True)
    args = parser.parse_args()
    return args

args= get_args()
nae_password = getpass.getpass()

#Create NAE Object
nae = cnae.NAE (args.nae_ip)   
#Log in to NAE with user and password
nae.login(args.user, nae_password,args.domain)

#Get all the data and save it as JSON
data =  nae.getTcamStats(args.ag_name)
fileName = 'TCAM_Stats_' + args.ag_name + '.json'
with open(fileName, 'w') as outfile:
        json.dump(data, outfile)

