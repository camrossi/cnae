import requests
import sys
import logging
import json
from pprint import pprint
import time
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

class NAE:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.session_cookie = {}
        self.assuranceGroups = {}
        self.http_header = {'Host' : self.ip_addr,'Content-type':'application/json;charset=utf-8'}

        # create logger
        self.logger = logging.getLogger(__name__)
        
        
        # create console handler and set level to debug
        self.ch = logging.StreamHandler()
        self.ch.setLevel(logging.DEBUG)
        
        # create formatter
        self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        # add formatter to ch
        self.ch.setFormatter(self.formatter)
        
        # add ch to logger
        self.logger.addHandler(self.ch)
        
        #Disable URL Lib Warnings
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)




    def login(self, user, password, domain):
        self.logger.debug("Log In to NAE")
    
        url = 'https://'+self.ip_addr+'/api/v1/whoami'
    
        req = requests.get(url, headers=self.http_header, verify=False)
        self.session_cookie['SESSION'] = req.cookies['SESSION']
    
        url = 'https://'+self.ip_addr+'/api/v1/login'
    
        self.http_header['X-CANDID-LOGIN-OTP'] = req.headers['X-CANDID-LOGIN-OTP']
        
        user_credentials =json.dumps({"username": user, "password": password, "domain": domain})
    
        req = requests.post(url, data=user_credentials, headers=self.http_header,cookies=self.session_cookie, verify=False)
        if req.json()['success']:
            self.logger.info("Login Successful")
        else:
            self.logger.info("Login failed")
            exit()

        
        # Save the Candid CSRF token, is needed when we do POSTs. 
        self.http_header['X-CANDID-CSRF-TOKEN'] = req.headers['X-CANDID-CSRF-TOKEN']

        # Update with the authenticated Cookie
        self.session_cookie['SESSION'] = req.cookies['SESSION']

        #Remove the LOGIN-OTP from header, is only needed at the beginning 
        self.http_header.pop('X-CANDID-LOGIN-OTP', None)

        
    #This method will get the list of all the assurance groups
    def getAllAG(self): 
        url = 'https://'+self.ip_addr+'/api/v1/config-services/assured-networks/aci-fabric/'
        req = requests.get(url, headers=self.http_header, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.assuranceGroups = req.json()['value']['data']
            self.logger.debug("Update all the assurange groups data")

    def getAG(self, name):
        self.getAllAG()
        for ag in self.assuranceGroups:
            if ag['unique_name'] == name:
                return ag
        return None

    def isLiveAnalysis(self):
        self.getAllAG()
        for ag in self.assuranceGroups:
            if ag['status'] == "RUNNING" and 'iterations' not in ag:
                self.logger.debug("There is a Live Analysis running:wa on Assurance Group %s",ag['unique_name'])
                return ag['unique_name']

    def isOnDemandAnalysis(self):
        self.getAllAG()
        for ag in self.assuranceGroups:
            if ag['status'] == "RUNNING" and 'iterations' in ag:
                self.logger.debug("There is a Running OnDemand Analysis on Assurance Group %s",ag['unique_name'])
                return ag['unique_name']
            


    def StartOnDemandAnalysis(self, ag_name, iterations):

        self.logger.info("Trying to Starting Analysis on Assurance Group %s",ag_name)
        runningLive = self.isLiveAnalysis()
        runningOnDemand = self.isOnDemandAnalysis()

        if runningLive:
            self.logger.info("There is currently a Live analysis on %s, please stop it manually and try again", runningLive)
            exit()
        
        elif runningOnDemand :
            self.logger.info("There is currently an OnDemand analysis running on %s, will try again in 2minutes", runningOnDemand)
            return False
        else:
             
            ag = self.getAG(ag_name)

            if ag == None:
                self.logger.info("The %s assurance group does not exist",ag_name)
                exit()

            ag_iterations = json.dumps({'iterations': iterations})
            url = 'https://'+self.ip_addr+'/api/v1/config-services/assured-networks/aci-fabric/'+ag['uuid']+'/start-analysis'
            req = requests.post(url, data=ag_iterations, headers=self.http_header,cookies=self.session_cookie, verify=False)
            if req.status_code == 200:
                self.logger.info('Successfully started OnDemand Analysis on %s', ag_name)
                return True
            else:
                self.logger.info('OnDemand Analysis failed to start on %s.', ag_name)
                pprint(req.json())
                exit()

    def StopLiveAnalysis(self,ag_name):
        current_ondemand = isOnDemandAnalysis()
        if current_ondemand == ag_name:
            pass
        

        
        













    



