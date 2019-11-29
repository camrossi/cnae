# Example Script on how to usee getTcamStats
import cnae
import logging
import time
import argparse
import getpass
from pprint import pprint


# Enble logging at debug level
logger = logging.getLogger('cnae')
logger.setLevel(logging.INFO)


nae_password= 'pass'
#Create NAE Object
nae = cnae.NAE ('IP')   
#Log in to NAE with user and password
nae.login("admin", nae_password,"Local")

#Get all the data and save it as JSON
data =  nae.getTcamStats("AG_NAME")
with open('Tcam.json', 'w') as outfile:
        json.dump(data, outfile)

