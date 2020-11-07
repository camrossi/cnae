import hashlib
import requests
import filelock 
import pathlib
import sys
import os
import logging
import json
from pprint import pprint
import time
import json
import parseJSON
import time
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests_toolbelt import MultipartEncoder



class NAE:
    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.session_cookie = {}
        self.assuranceGroups = {}
        self.files = {}
        self.version = ""
        self.http_headers = {'Accept': 'application/json, text/plain, */*',
                            'Accept-Encoding': 'gzip, deflate, br',
                            'Accept-Language':'en-GB,en-US;q=0.9,en;q=0.8,it;q=0.7',
                            'Sec-Fetch-Mode': 'cors',
                            'Sec-Fetch-Site': 'same-origin',
                            'Host' : self.ip_addr,
                            'Content-Type':'application/json;charset=utf-8', 
                            }
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
    
        
        url = 'https://'+self.ip_addr+'/nae/api/v1/whoami'
        req = requests.get(url, headers=self.http_headers, verify=False)
        #Save all the cookies
        self.session_cookie = req.cookies
    
        url = 'https://'+self.ip_addr+'/nae/api/v1/login'
    
        self.http_headers['X-NAE-LOGIN-OTP'] = req.headers['X-NAE-LOGIN-OTP']
        
        user_credentials =json.dumps({"username": user, "password": password, "domain": domain})
    
        req = requests.post(url, data=user_credentials, headers=self.http_headers,cookies=self.session_cookie, verify=False)
        if req.json()['success']:
            self.logger.info("Login Successful")
        else:
            self.logger.info("Login failed")
            exit()

        
        # Save the Candid CSRF token, is needed when we do POSTs. 
        self.http_headers['X-NAE-CSRF-TOKEN'] = req.headers['X-NAE-CSRF-TOKEN']

        # Update with the authenticated Cookie
        self.session_cookie['SESSION'] = req.cookies['SESSION']

        #Remove the LOGIN-OTP from header, it is only needed at the beginning 
        self.http_headers.pop('X-NAE-LOGIN-OTP', None)

        #Get NAE Version
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/candid-version'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.version = req.json()['value']['data']['candid_version']
            self.logger.info("NAE Version %s", self.version)
        else:
            self.logger.info("Unable to determine system version")
            exit()

        
    #This method will get the list of all the assurance groups
    def getAllAG(self): 
        url = 'https://'+self.ip_addr+'/nae/api/v1/config-services/assured-networks/aci-fabric/'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.assuranceGroups = req.json()['value']['data']
            self.logger.debug("Update all the assurange groups data")
        else:
            self.logger.info("No Assurance Group are present")
            
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

        url=  'https://'+self.ip_addr+'/nae/api/v1/config-services/assured-networks/aci-fabric/'

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
       
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
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
            if (ag['status'] == "RUNNING" or ag['status'] == "ANALYSIS_NOT_STARTED" or ag['status'] == "ANALYSIS_IN_PROGRESS")  and ('iterations' in ag):
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
            url = 'https://'+self.ip_addr+'/nae/api/v1/config-services/assured-networks/aci-fabric/'+ag['uuid']+'/start-analysis'
            req = requests.post(url, data=ag_iterations, headers=self.http_headers,cookies=self.session_cookie, verify=False)
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
            self.logger.info("There is currently an  analysis running  will try again in 30 seconds. \n If is a live analysis please stop it manually")
            time.sleep(30)

        form = '''{
          "unique_name": "''' + name + '''",
          "file_upload_uuid": "''' + fileID +'''",
          "aci_fabric_uuid": "''' + fabricID + '''",
          "analysis_timeout_in_secs": 3600
        }'''
        
        if '4.0' in self.version:
            url ='https://'+self.ip_addr+'/nae/api/v1/event-services/offline-analysis'
            req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
            if req.status_code == 202:
                self.logger.info("Offline Analysis %s Started", name)
            else:
                self.logger.info("Offline Analysis creation failed with error message \n %s",req.content)

        
        elif '4.1' in self.version or '5.0' in  self.version or '5.1' in self.version:
            #in 4.1 starting an offline analysis is composed of 2 steps
            # 1 Create the Offline analysis
            url ='https://'+self.ip_addr+'/nae/api/v1/config-services/offline-analysis'
            req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
            if req.status_code == 202:
                self.logger.info("Offline Analysis %s Created", name)
                pprint(req.json()['value']['data'])
                #Get the analysis UUID:
                analysis_id = req.json()['value']['data']['uuid']

                url ='https://'+self.ip_addr+'/nae/api/v1/config-services/analysis'

                form = '''{
                  "interval": 300,
                  "type": "OFFLINE",
                  "assurance_group_list": [
                    {
                      "uuid": "''' + fabricID + '''"
                    }
                  ],
                  "offline_analysis_list": [
                    {
                      "uuid":"''' + analysis_id + '''" 
                    }
                  ],
                  "iterations": 1
                }'''

                req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
                if req.status_code == 202 or req.status_code == 200 :
                    self.logger.info("Offline Analysis %s Started", name)
                    #Sleeping 10s as it takes a moment for the status to be updated. 
                    time.sleep(10)
                else:
                    self.logger.info("Offline Analysis creation failed with error message \n %s",req.content)

        else:
                self.logger.info("Unsupported version")

    def getFiles(self):
        #This methods loads all the uploaded files to NAE
        url = 'https://'+self.ip_addr+'/nae/api/v1/file-services/upload-file'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        self.files = req.json()['value']['data']


    def updateLicense(self,license):
        pass

    def getApplianceID(self):
        # Get Appliance ID
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/candid-version'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']['candid_appliance_id'].strip()


    def StopLiveAnalysis(self,ag_name):
        current_ondemand = isOnDemandAnalysis()
        if current_ondemand == ag_name:
            pass
        
    def getObjectSelector(self, os_name, ag_name):
        # Get all object selectors and return them as a dictionary
        ag = self.getAG(ag_name)
        #Get the list of Object Selectors 
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/' + ag + '/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        os_list = req.response()
        pprint(os_list)

    
    def newObjectSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Object Selectors created")
        else:
           self.logger.info("Object Selectors creation failed with error message \n %s",req.json())

    def newTrafficSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/traffic-selectors'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Traffic Selectors created")
        else:
           self.logger.info("Traffic Selectors creation failed with error message \n %s",req.json())

    def newComplianceRequirement(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirements'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Compliance Requirement created")
        else:
           self.logger.info("Compliance Requirement creation failed with error message \n %s",req.json())

    def newComplianceRequirementSet(self, form):
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirement-sets'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Complianc Requirement Set created")
        else:
           self.logger.info("Complianc Requirement Set creation failed with error message \n %s",req.json())
   
    def newDeltaAnalysis(self,name, prior_epoch_uuid, later_epoch_uuid):
        url = 'https://'+self.ip_addr+'/nae/api/v1/job-services'
        form = '''{
               "type": "EPOCH_DELTA_ANALYSIS",
               "name": "''' + name + '''",
               "parameters": [
                   {
                       "name": "prior_epoch_uuid",
                       "value": "''' + prior_epoch_uuid + '''"
                   },
                   {
                       "name": "later_epoch_uuid",
                       "value": "''' + later_epoch_uuid + '''"
                   }
                   ]
               }'''
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 202:
           self.logger.info("Delta analysis %s created", name)
        else:
           self.logger.info("Delta analysis creation failed with error message \n %s",req.json())



    def getEpochs(self, fabricName, pcv = True):
        print("Getting Epochs....")
        #Get all the epochs (sorted from oldest to new from a fabric. ToDo Add filter support based on times
        # By default I drop all the epoch of type Pre Change Verification. 

        fabric = self.getAG(fabricName)            
        url =  u'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+str(fabric['uuid'])+'/epochs?$sort=collectionTimestamp'
        self.logger.info("Getting Epochs for fabric %s", fabric['unique_name'])
             
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        #return all the the Epochs
        if pcv:
            return req.json()['value']['data']
        #Return all but PCV
        else:
            #4.0 does not have PVC so there is no epoch_type key. 
            if '4.0' in self.version:
                return req.json()['value']['data']
            elif '4.1' or '5.0' in self.version:
                return [i for i in req.json()['value']['data'] if not (i['epoch_type'] == 'PCV')]
           

    def getAllReqSets(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirement-sets'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']

    def getAllReq(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirements'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']

    def getAllTrafficSelectors(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/traffic-selectors'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']

    def getAllObjSelectors(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']


    def deleteAG(self, obj):
        url = u'https://'+self.ip_addr+'/nae/api/v1/config-services/assured-networks/aci-fabric/' + obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Assurance group %s", obj['unique_name'])
        else:
            self.logger.info("Deleting Assurance group %s failed with error %s",obj['unique_name'], req.json())

    def deleteReqSet(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/requirement-sets/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Requirement Set %s", obj['name'])
        else:
            self.logger.info("Deleting Requirement Set %s failed with error %s",obj['name'], req.json())

    def deleteReq(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/requirements/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Requirement %s", obj['name'])
        else:
            self.logger.info("Deleting Requirement %s failed with error %s",obj['name'], req.json())

    def deleteObjSelector(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/object-selectors/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Object Selector %s", obj['name'])
        else:
            self.logger.info("Deleting Object Selector %s failed with error %s",obj['name'], req.json())

    def deleteTrafficSelector(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/traffic-selectors/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted traffic-selector %s", obj['name'])
        else:
            self.logger.info("Deleting traffic-selector %s failed with error %s",obj['name'], req.json())

    def newManualPCV(self, changes, ag_name,name, description):
        
        while self.isOnDemandAnalysis() or self.isLiveAnalysis():
            self.logger.info("There is currently an  analysis running  will try again in 2 minutes. \n If is a live analysis please stop it manually")
            time.sleep(120)
       
        fabric_id = str(self.getAG(ag_name)['uuid'])
        base_epoch_id = self.getEpochs(ag_name,False)[-1]["epoch_id"]
        if '4.1' in self.version:
            f = None
            fields = {
                    ('data', 
                        (f,
                        
                            # content to upload 
                                '''{
                                    "name": "''' + name + '''",
                                    "fabric_uuid": "''' + fabric_id + '''",
                                    "base_epoch_id": "''' + base_epoch_id + '''",
                                    
                                    "changes": ''' + changes + ''',
                                    "stop_analysis": false,
                                    "change_type": "CHANGE_LIST"
                                    }'''
                            # The content type of the file
                            , 'application/json'))
                    }
            url = 'https://'+self.ip_addr+'/nae/api/v1/config-services/prechange-analysis'  
            m = MultipartEncoder(fields=fields)
            h = self.http_headers
            h['Content-Type']= m.content_type
            req = requests.post(url, data=m,  headers=h, cookies=self.session_cookie, verify=False) 
 
        elif '5.0' in  self.version or '5.1' in  self.version:
            url = 'https://'+self.ip_addr+'/nae/api/v1/config-services/prechange-analysis/manual-changes?action=RUN'
            form = '''{
                                    "name": "''' + name + '''",
                                    "allow_unsupported_object_modification": true,
                                    "uploaded_file_name": null,
                                    "stop_analysis": false,
                                    "fabric_uuid": "''' + fabric_id + '''",
                                    "base_epoch_id": "''' + base_epoch_id + '''",
                                    "imdata": ''' + changes + '''
                                    }'''

            req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)

        if req.status_code == 200:
           self.logger.info('Pre-Change analysis "' + name + '" created.')
        else:
          self.logger.info("Error %s", req.content)    


    
    def getPreChangeAnalyses(self, ag_name, out_flag):
        fabric_id = str(self.getAG(ag_name)['uuid'])
        url = 'https://'+self.ip_addr+'/nae/api/v1/config-services/prechange-analysis?fabric_id='+fabric_id
        response = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if(out_flag):
            parseJSON.getAnalyses(response)
        return response.json()['value']['data']
        
    def deletePreChangeAnalysis(self,ag_name,pre_change_analysis_name):
        job_id = str(self.getPreChangeAnalysis(ag_name,pre_change_analysis_name)['job_id'])
        url = 'https://'+self.ip_addr+'/nae/api/v1/config-services/prechange-analysis/'+job_id
        response = requests.delete(url,headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return response.json()['value']['data']

    def getPreChangeAnalysis(self, ag_name, pre_change_analysis_name):
        ret = self.getPreChangeAnalyses(ag_name,False)
        for a in ret:
            if a['name'] == pre_change_analysis_name:
                return a
        return None
    
    def getPreChangeResult(self,ag_name, pre_change_analysis_name, verbose_flag): 
        fabric_id = str(self.getAG(ag_name)['uuid'])
        early_epoch_id = str(self.getPreChangeAnalysis(ag_name,pre_change_analysis_name)['base_epoch_id'])
        epoch_delta_job_id = str(self.getPreChangeAnalysis(ag_name,pre_change_analysis_name)['epoch_delta_job_id'])
        # print(str(self.getPreChangeAnalysis(ag_name,pre_change_analysis_name)['epoch_delta_job_id']))
        analysis_status = str(self.getPreChangeAnalysis(ag_name,pre_change_analysis_name)['analysis_status'])
        #if(analysis_status == "SUBMITTTED"):
        #    self.logger.info("Pre-change analysis " + pre_change_analysis_name + " not completed. Status: Submitted.")
        #    return "SUBMITTTED"
        #if(analysis_status == "RUNNING"):
        #    self.logger.info("Pre-change analysis " + pre_change_analysis_name + " not completed. Status: Running.")
        #    return "RUNNING"
        if analysis_status == "COMPLETED":
            later_epoch_id = str(self.getPreChangeAnalysis(ag_name,pre_change_analysis_name)['pre_change_epoch_uuid'])
            analysis_id = str(self.getPreChangeAnalysis(ag_name,pre_change_analysis_name)['epoch_delta_job_id'])
            no_response = False
            url = 'https://'+self.ip_addr+'/nae/api/v1/epoch-delta-services/assured-networks/'+fabric_id+'/job/'+analysis_id+'/health/view/event-severity'
            url_later = 'https://'+self.ip_addr+'/nae/api/v1/epoch-delta-services/assured-networks/'+fabric_id+'/job/'+epoch_delta_job_id+'/health/view/aggregate-table?category=ADC,CHANGE_ANALYSIS,TENANT_ENDPOINT,TENANT_FORWARDING,TENANT_SECURITY,RESOURCE_UTILIZATION,SYSTEM,COMPLIANCE&epoch_status=EPOCH2_ONLY&severity=EVENT_SEVERITY_CRITICAL,EVENT_SEVERITY_MAJOR,EVENT_SEVERITY_MINOR,EVENT_SEVERITY_WARNING,EVENT_SEVERITY_INFO'
            response = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
            response_later = requests.get(url_later, headers=self.http_headers, cookies=self.session_cookie, verify=False)      
            response = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
            self.logger.info("<======== SMART EVENT COUNT ========>")
            if(verbose_flag):
                table_url = 'https://'+self.ip_addr+'/nae/api/v1/epoch-delta-services/assured-networks/'+fabric_id+'/job/'+analysis_id+'/health/view/aggregate-table'
                table_response = requests.get(table_url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
                parse_table = parseJSON.Parser(response)
                return parse_table.ParsePreChangeResults(response_later,parse_table.obj,pre_change_analysis_name,verbose_flag,table_response,early_epoch_id,later_epoch_id)
            parse = parseJSON.Parser(response)
            return parse.ParsePreChangeResults(response_later,parse.obj,pre_change_analysis_name,verbose_flag,no_response,early_epoch_id,later_epoch_id)
        else:
            self.logger.info("Pre-change analysis " + pre_change_analysis_name + " not completed")
            return "RUNNING"
       

    def getTcamStats(self,ag_name):
        fabric_id = str(self.getAG(ag_name)['uuid'])
        latest_epoch = self.getEpochs(ag_name)[-1]['epoch_id']
        #latest_epoch = "737ea995-b313f61d-6e6f-3971-9b34-809269d6a693"
        self.logger.debug("last epoch id is %s", latest_epoch)
        page = 0
        objPerPage=200
        has_more_data = True
        tcam_data = []
        # As long as there is more data get it
        while has_more_data:  
            self.logger.info("Requesting %d objects per page", objPerPage)            
            #I get data sorter by tcam hists for hitcount-by-rules --> hitcount-by-epgpair-contract-filter
            url = 'https://'+self.ip_addr+'/nae/api/v1/event-services/assured-networks/' + fabric_id +'/model/aci-policy/tcam/hitcount-by-rules/hitcount-by-epgpair-contract-filter?$epoch_id='+latest_epoch+'&$page='+str(page)+'&$size='+str(objPerPage)+'&$sort=-cumulative_count&$view=histogram'
            start = time.time()
            req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
            end = time.time()
            if req.status_code == 200:
                self.logger.info("Page retrieved")
            else:
                self.logger.info("error getting TCAM", req.json())
            page = page + 1
            has_more_data = req.json()['value']['data_summary']['has_more_data']
            total_pages =  req.json()['value']['data_summary']['total_page_count']
            actual_page_size =  req.json()['value']['data_summary']['page_size']
            tcam_data.append((req.json()['value']['data']))
            self.logger.info("Page %d/%d processed in %d seconds", page, total_pages, end - start)
            self.logger.info("Requested Page size %d. Actual Page Size %d", objPerPage, actual_page_size)
        self.logger.info("Pages extracted %d", page)
        return tcam_data
    def nae_rest(self, api_ep, payload):
        url = 'https://'+self.ip_addr+ api_ep
        print(url)
        print(payload)
        response = requests.post(url, data=payload, headers=self.http_headers,cookies=self.session_cookie, verify=False)
        return response.json()
    
    def wipe(self, keep_offline_files):
        #Delete all Assurance Groups
        self.getAllAG()
        for ag in self.assuranceGroups:
            self.deleteAG(ag)

        #Create a dummy AG to be able to then delete all the requirement sets (I found this faster than disassociating the requires sets from every AG)
        self.newOfflineAG("Dummy")
        ag = self.getAG("Dummy")
        ag_uuid = ag['uuid']


        for i in self.getAllReqSets():
            self.deleteReqSet(ag_uuid, i)

        for i in self.getAllReq():
            self.deleteReq(ag_uuid, i)
       
        for i in self.getAllTrafficSelectors():
            self.deleteTrafficSelector(ag_uuid, i)

        for i in self.getAllObjSelectors():
            self.deleteObjSelector(ag_uuid, i)
        # Delete dummy AG
        for ag in self.assuranceGroups:
            self.deleteAG(ag)

    def get_logout_lock(self):
        # This lock has been introduced because logout and file upload cannot be
        # done in parallel. This is because logout incorrectly aborts all file
        # uploads by a user (not just that session). So, this lock must be
        # acquired for logout and file upload.
        lock_filename = "logout.lock"
        try:
            pathlib.Path(lock_filename).touch(exist_ok=False)
        except OSError:
            pass
        return filelock.FileLock(lock_filename)

    def upload_file(self, unique_name, file_path, fabric_uuid=None):
        file_upload_uuid = None
        uri = 'https://'+self.ip_addr + "/nae/api/v1/file-services/upload-file"
        try:
            with self.get_logout_lock():
                chunk_url = self.start_upload(unique_name, file_path, uri, 'OFFLINE_ANALYSIS', fabric_uuid)
                complete_url = None
                if chunk_url:
                    complete_url = self.upload_file_by_chunk(chunk_url, file_path)
                else:
                    self.logger.error("Failed to start upload")
                if complete_url:
                    self.logger.info("Complete Url {} ".format(complete_url))
                    file_upload_uuid = self.complete_upload(complete_url)['uuid']
                else:
                    self.logger.error("Failed to upload file chunks.")
            return file_upload_uuid
        except Exception as e:
            print("some error occoured while uploading file")
            exc_type, exc_obj, tb = sys.exc_info()
            #self.logger.error(PrintException.printException(exc_type, exc_obj, tb))
            #print((PrintException.printException(exc_type, exc_obj, tb)))
            raise e

        return all_files_status

    def start_upload(self, unique_name, file_path, uri, upload_type, fabric_uuid=None, file_name=None):
        """
        Pass metadata to api and trigger start of upload file.

        Args:
            unique_name: str: name of upload
            file_name:  str:  file name of upload
            file_path:  str: path of file
            fabric_uuid: str: offline fabric id
            uri: str: uri
            upload_type: str: offline file/nat file
        Returns:
            str: chunk url , used for uploading chunks
                  or None if there was an issue starting
        """
        file_size_in_bytes = os.path.getsize(file_path)
        if not file_name:
            file_name = os.path.basename(file_path)
        args = {"data": {"unique_name": unique_name,
                         "filename": file_name,
                         "size_in_bytes": int(file_size_in_bytes),
                         "upload_type": upload_type}}  # "OFFLINE_ANALYSIS"
        response = requests.post(uri, data=json.dumps(args['data']), headers=self.http_headers,cookies=self.session_cookie, verify=False)
        if response and response.status_code == 201:
            print((str(response.json()['value']['data']['links'][-1]['href'])))
            return str(response.json()['value']['data']['links'][-1]['href'])
        self.logger.error("Failed to start upload of file {}".format(file_path))
        return None

    def upload_file_by_chunk(self, chunk_url, file_path):
        """Pass metadata to api and trigger start of upload file.

        Args:
           chunk_url: str: url to send chunks
           file_path: str: path of file and filename

        Returns:
            str: chunk url , used for uploading chunks or None if issue uploading
        """
        try:
            chunk_id = 0
            offset = 0
            self.logger.info("chunk_id:{}".format(chunk_id))
            self.logger.info("offset:{}".format(offset))
            chunk_uri = 'https://'+self.ip_addr + '/nae' + chunk_url[chunk_url.index('/api/'):]
            self.logger.info("chunk_uri:{}".format(chunk_uri))
            response = None
            file_size_in_bytes = os.path.getsize(file_path)
            self.logger.info("file_path:{}".format(file_path))
            self.logger.info("file_size_in_bytes:{}".format(file_size_in_bytes))
            chunk_byte_size = 10000000
            if file_size_in_bytes < chunk_byte_size:
                chunk_byte_size = int(file_size_in_bytes // 2)
            with open(file_path, 'rb') as f:
                for chunk in self.read_in_chunks(f, chunk_byte_size):
                    checksum = hashlib.md5(chunk).hexdigest()
                    chunk_info = {"offset": int(offset),
                                  "checksum": checksum,
                                  "chunk_id": chunk_id,
                                  "size_in_bytes": sys.getsizeof(chunk)}
                    files = {"chunk-info": (None, json.dumps(chunk_info),
                                            'application/json'),
                             "chunk-data": (os.path.basename(file_path) +
                                            str(chunk_id),
                                            chunk, 'application/octet-stream')}
                    args = {"files": files}
                    chunk_headers = self.http_headers.copy()
                    chunk_headers.pop("Content-Type",None)
                    response = requests.post(chunk_uri, data = None, files=args['files'], headers=chunk_headers,cookies=self.session_cookie, verify=False)
                  #  response = self.post(chunk_uri, **args)
                    chunk_id += 1
                    if response and response.status_code != 201:
                        self.logger.error(
                            "Incorrect response code: {} ".format(response.json()))
                        return None
                if response:
                    self.logger.info("upload {}".format(response.text))
                    return str(response.json()['value']['data']['links'][-1]['href'])
                else:
                    print("no response received while uploading chuks")
                    print(response.text)
                    self.logger.error('no response received while uploading chunks')
        except IOError as ioex:
            self.logger.error("Cannot open: {}".format(file_path))
        return None

    def read_in_chunks(self, file_object, chunk_byte_size):
        """
        Return chunks of file.

        Args:
           file_object: file: open file object
           chunk_byte_size: int: size of chunk to return

        Returns:
            Returns a chunk of the file
        """
        while True:
            data = file_object.read(chunk_byte_size)
            if not data:
                break
            yield data

    def complete_upload(self, complete_url):
        """Complete request to start dag.

        Args:
           chunk_url: str: url to complte upload and start dag

        Returns:
            str: uuid or None

        NOTE: Modified function to not fail if epoch is at scale.
        Scale epochs sometimes take longer to upload and in that
        case, the api returns a timeout even though the upload
        completes successfully later.
        """
        timeout = 300
        complete_uri = 'https://'+self.ip_addr + '/nae' + complete_url[complete_url.index('/api/'):]
        #response = self.post(complete_uri, timeout=240)
        response = requests.post(complete_uri, headers=self.http_headers,cookies=self.session_cookie, verify=False)
        try:
            if response and response.status_code == 200:
                self.logger.info("complete_upload response {}".format(
                                    str(response.json())))
                return response.json()['value']['data']
            elif not response or response.status_code == 400:
                self.logger.info('hit the case when complete timed out. Will busy wait checking status till timeout')
                total_time = 0
                while total_time < timeout:
                    time.sleep(10)
                    total_time += 10
                    response = self.get('https://'+self.ip_addr +'/nae/api/v1/file-services/upload-file')
                    if response and response.status_code == 200:
                        resp = response.json()
                        uuid = complete_url.split('/')[-2]
                        for offline_file in resp['value']['data']:
                            if offline_file['uuid'] == uuid:
                                success = offline_file['status'] == 'UPLOAD_COMPLETED'
                                if success:
                                    self.logger.info('finally completed scale epoch successfully')
                                    return {'uuid': offline_file['uuid']}

            # IF I REACHED HERE... SOMETHING IS WRONG
            self.logger.info('no upload completed')
            raise Exception
        except Exception as e:
            print("some error occoured while completing the upload")
            exc_type, exc_obj, tb = sys.exc_info()
            #self.logger.error(PrintException.printException(exc_type, exc_obj, tb))
            #print((PrintException.printException(exc_type, exc_obj, tb)))
            raise e
    
    def get_most_idle_model(self): 
        #Unload the snapshot with higher idle time. There is no error control... 
        #Get active SnapShots
        url = 'https://'+self.ip_addr+'/nae/api/v1/connectivity-analysis-services/analysis/active'
        req = requests.get(url, headers=self.http_headers,cookies=self.session_cookie, verify=False)
        snaps = req.json()['value']['data']
        snaps = sorted(snaps, key=lambda k: k['idle_time_in_milli_secs'], reverse=True) 
        self.logger.debug("Snapsot {} has been idle for {}".format(snaps[0]['uuid'], snaps[0]['idle_time']))
        return snaps[0]['uuid']


    def can_epg(self,ag_name,query):
        fabric_id = str(self.getAG(ag_name)['uuid'])
        latest_epoch = self.getEpochs(ag_name)[-1]['epoch_id']
        offloaded_epoch_id = self.get_most_idle_model()
        self.logger.debug("Load epoch")

        url = 'https://'+self.ip_addr+'/nae/api/v1/connectivity-analysis-services/analysis'
        #I should only set offloaded_epoch_id if I cna't load more epoch in memory but is just a demo piece of code
        form = '''{"snapshot_uuid":"''' + latest_epoch + '''",
                "offloaded_epoch_id":"''' + offloaded_epoch_id + '''"
                }'''
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
    
        self.logger.debug("last epoch id is %s", latest_epoch)
        url = 'https://'+self.ip_addr+'/nae/api/v1/connectivity-analysis-services/can-epg'
        form = '''{
        "query_str": "''' + query +'''",
        "snapshot_uuid":"''' + latest_epoch + '''"}'''
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return(req.json())