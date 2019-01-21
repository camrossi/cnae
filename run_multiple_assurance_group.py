import cnae
import logging
import time
import argparse
import getpass

# Enble logging at debug level
logger = logging.getLogger('cnae')
logger.setLevel(logging.INFO)

def get_args():
    parser = argparse.ArgumentParser(description="This app lets you run on a single NAE cluster multiple fabric")
    parser.add_argument('-u', dest='user', help='Username, default: admin', default='admin')
    parser.add_argument('-a', dest='ag_list', help='Assurance grop names space separated i.e.: FAB_1 FAB_2 FAB_N', nargs='+', required=True)
    parser.add_argument('-i', dest='nae_ip', help='IP address of the NAE Appliance',required=True)
    parser.add_argument('-d', dest='domain', help='Login Domain, defaul: Local',default='Local')
    args = parser.parse_args()
    return args


args= get_args()
nae_password = getpass.getpass()
#Create NAE Object
nae = cnae.NAE (args.nae_ip)

#Log in to NAE with user and password
nae.login(args.user, nae_password,args.domain)


while True:
    for ag_name in args.ag_list:
        # Keep trying to start an analysis. 
        while not nae.StartOnDemandAnalysis(ag_name,1):
            time.sleep(120)
