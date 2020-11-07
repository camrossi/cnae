import cnae
import logging
import time
import argparse
import getpass
from pprint import pprint
from prettytable import PrettyTable
# Enble logging at debug level
logger = logging.getLogger('cnae')
logger.setLevel(logging.DEBUG)

def get_args():
    parser = argparse.ArgumentParser(description="This app lets you run on a single NAE cluster multiple fabric")
    parser.add_argument('-u', dest='user', help='Username, default: admin', default='admin')
    parser.add_argument('-i', dest='nae_ip', help='IP address of the NAE Appliance',required=True)
    parser.add_argument('-d', dest='domain', help='Login Domain, defaul: Local',default='Local')
    args = parser.parse_args()
    return args


args= get_args()
#nae_password = getpass.getpass()
nae_password= 'C@ndidadmin1234'
#Create NAE Object
nae = cnae.NAE (args.nae_ip)

#Log in to NAE with user and password
nae.login(args.user, nae_password,args.domain)
query = "Can ep:1.1.1.100/32|00:50:56:B6:84:18 talk to EP:2.2.2.100/32|00:50:56:B6:A7:D1"
q = nae.can_epg('STLD_FAB1',query)
q = q['value']['data']
pprint(q)

