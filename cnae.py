import requests
import sys
import os
import logging
import json
from pprint import pprint
import time
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from selenium import webdriver

class NAE:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.session_cookie = {}
        self.assuranceGroups = {}
        self.files = {}
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
    
        self.http_header['X-NAE-LOGIN-OTP'] = req.headers['X-NAE-LOGIN-OTP']
        
        user_credentials =json.dumps({"username": user, "password": password, "domain": domain})
    
        req = requests.post(url, data=user_credentials, headers=self.http_header,cookies=self.session_cookie, verify=False)
        if req.json()['success']:
            self.logger.info("Login Successful")
        else:
            self.logger.info("Login failed")
            exit()

        
        # Save the Candid CSRF token, is needed when we do POSTs. 
        self.http_header['X-NAE-CSRF-TOKEN'] = req.headers['X-NAE-CSRF-TOKEN']

        # Update with the authenticated Cookie
        self.session_cookie['SESSION'] = req.cookies['SESSION']

        #Remove the LOGIN-OTP from header, is only needed at the beginning 
        self.http_header.pop('X-NAE-LOGIN-OTP', None)

        
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
    
    def getFirstAG(self):
        # Some API requires an Assurance grup in the API call even if does not matter which AG you select
        # For this I have created this methodggGG
        self.getAllAG()
        return self.assuranceGroups[0]        
        

    def newOfflineAG(self, name):
        # This method creates a new Offline Assurance Group, you only need to pass the AG Name.

        url=  'https://'+self.ip_addr+'/api/v1/config-services/assured-networks/aci-fabric/'

        form ='''{
          "analysis_id": "",
          "display_name": "",
          "description": "",
          "operational_mode": "OFFLINE",
          "status": "STOPPED",
          "active": true,
          "unique_name": "''' + name + '''",
          "assured_network_type": "",
          "analysis_timeout_in_secs": 3600,
          "apic_configuration_export_policy": {
            "apic_configuration_export_policy_enabled": false,
            "export_format": "XML",
            "export_policy_name": ""
          },
          "analysis_schedule_id": ""}'''
       
        req = requests.post(url, data=form,  headers=self.http_header, cookies=self.session_cookie, verify=False)
        if req.status_code == 201:
             self.logger.info("Assurange group %s created", name)
        else:
             self.logger.info("Assurange Group creation failed with error message \n %s",req.json())

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

    def newOfflineAnalysis(self, name, fileID, fabricID):
        self.logger.info("Trying to Starting Analysis  %s",name)
        
        while self.isOnDemandAnalysis() or self.isLiveAnalysis():
            self.logger.info("There is currently an  analysis running  will try again in 2 minutes. \n If is a live analysis please stop it manually")
            time.sleep(120)

        form = '''{
          "unique_name": "''' + name + '''",
          "file_upload_uuid": "''' + fileID +'''",
          "aci_fabric_uuid": "''' + fabricID + '''",
          "analysis_timeout_in_secs": 3600
        }'''
        url ='https://'+self.ip_addr+'/api/v1/event-services/offline-analysis'
        req = requests.post(url, data=form,  headers=self.http_header, cookies=self.session_cookie, verify=False)
        pprint(req)
        if req.status_code == 202:
            self.logger.info("Offline Analysis %s Started", name)
        else:
            self.logger.info("Offline Analysis creation failed with error message \n %s",req.content)

    def getFiles(self):
        #This methods loads all the uploaded files to NAE
        url = 'https://'+self.ip_addr+'/api/v1/file-services/upload-file'
        req = requests.get(url, headers=self.http_header, cookies=self.session_cookie, verify=False)
        self.files = req.json()['value']['data']


    def updateLicense(self,license):
        pass

    def getApplianceID(self):
        # Get Appliance ID
        url = 'https://'+self.ip_addr+'/api/v1/event-services/candid-version'
        req = requests.get(url, headers=self.http_header, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']['candid_appliance_id'].strip()


    def StopLiveAnalysis(self,ag_name):
        current_ondemand = isOnDemandAnalysis()
        if current_ondemand == ag_name:
            pass
        
    def getObjectSelector(self, os_name, ag_name):
        # Get all object selectors and return them as a dictionary
        ag = self.getAG(ag_name)
        #Get the list of Object Selectors 
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/' + ag + '/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.get(url, headers=self.http_header, cookies=self.session_cookie, verify=False)
        os_list = req.response()
        pprint(os_list)

    
    def newObjectSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.post(url, data=form,  headers=self.http_header, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Object Selectors created")
        else:
           self.logger.info("Object Selectors creation failed with error message \n %s",req.json())

    def newTrafficSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/traffic-selectors'
        req = requests.post(url, data=form,  headers=self.http_header, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Traffic Selectors created")
        else:
           self.logger.info("Traffic Selectors creation failed with error message \n %s",req.json())

    def newComplianceRequirement(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirements'
        req = requests.post(url, data=form,  headers=self.http_header, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Complianc Requirement created")
        else:
           self.logger.info("Complianc Requirement creation failed with error message \n %s",req.json())

    def newComplianceRequirementSet(self, form):
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirement-sets'
        req = requests.post(url, data=form,  headers=self.http_header, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Complianc Requirement Set created")
        else:
           self.logger.info("Complianc Requirement Set creation failed with error message \n %s",req.json())
    
