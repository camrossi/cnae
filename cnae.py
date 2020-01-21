import requests
import sys
import os
import logging
import json
from pprint import pprint
import time
import json
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
    
        
        url = 'https://'+self.ip_addr+'/api/v1/whoami'
    
        req = requests.get(url, headers=self.http_headers, verify=False)
        #Save all the cookies
        self.session_cookie = req.cookies
    
        url = 'https://'+self.ip_addr+'/api/v1/login'
    
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

        #Remove the LOGIN-OTP from header, is only needed at the beginning 
        self.http_headers.pop('X-NAE-LOGIN-OTP', None)

        #Get NAE Version
        url = 'https://'+self.ip_addr+'/api/v1/event-services/candid-version'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.version = req.json()['value']['data']['candid_version']
            self.logger.info("NAE Version %s", self.version)
        else:
            self.logger.info("Unable to determine system version")
            exit()

        
    #This method will get the list of all the assurance groups
    def getAllAG(self): 
        url = 'https://'+self.ip_addr+'/api/v1/config-services/assured-networks/aci-fabric/'
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
            self.logger.info("There is currently an  analysis running  will try again in 2 minutes. \n If is a live analysis please stop it manually")
            time.sleep(120)

        form = '''{
          "unique_name": "''' + name + '''",
          "file_upload_uuid": "''' + fileID +'''",
          "aci_fabric_uuid": "''' + fabricID + '''",
          "analysis_timeout_in_secs": 3600
        }'''
        
        if '4.0' in self.version:
            url ='https://'+self.ip_addr+'/api/v1/event-services/offline-analysis'
            req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
            if req.status_code == 202:
                self.logger.info("Offline Analysis %s Started", name)
            else:
                self.logger.info("Offline Analysis creation failed with error message \n %s",req.content)

        
        elif '4.1' in self.version:
            #in 4.1 starting an offline analysis is composed of 2 steps
            # 1 Create the Offline analysis
            url ='https://'+self.ip_addr+'/api/v1/config-services/offline-analysis'
            req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
            if req.status_code == 202:
                self.logger.info("Offline Analysis %s Created", name)
                pprint(req.json()['value']['data'])
                #Get the analysis UUID:
                analysis_id = req.json()['value']['data']['uuid']

                url ='https://'+self.ip_addr+'/api/v1/config-services/analysis'

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
                if req.status_code == 202:
                    self.logger.info("Offline Analysis %s Started", name)
                else:
                    self.logger.info("Offline Analysis creation failed with error message \n %s",req.content)

        else:
                self.logger.info("Offline Analysis creation failed with error message \n %s",req.content) 

    def getFiles(self):
        #This methods loads all the uploaded files to NAE
        url = 'https://'+self.ip_addr+'/api/v1/file-services/upload-file'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        self.files = req.json()['value']['data']


    def updateLicense(self,license):
        pass

    def getApplianceID(self):
        # Get Appliance ID
        url = 'https://'+self.ip_addr+'/api/v1/event-services/candid-version'
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
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/' + ag + '/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        os_list = req.response()
        pprint(os_list)

    
    def newObjectSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Object Selectors created")
        else:
           self.logger.info("Object Selectors creation failed with error message \n %s",req.json())

    def newTrafficSelector(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/traffic-selectors'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Traffic Selectors created")
        else:
           self.logger.info("Traffic Selectors creation failed with error message \n %s",req.json())

    def newComplianceRequirement(self, form):
        ag = self.getFirstAG()
        url ='https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirements'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Compliance Requirement created")
        else:
           self.logger.info("Compliance Requirement creation failed with error message \n %s",req.json())

    def newComplianceRequirementSet(self, form):
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirement-sets'
        req = requests.post(url, data=form,  headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
           self.logger.info("Complianc Requirement Set created")
        else:
           self.logger.info("Complianc Requirement Set creation failed with error message \n %s",req.json())
   
    def newDelataAnalysis(self,name, prior_epoch_uuid, later_epoch_uuid):
        url = 'https://'+self.ip_addr+'/api/v1/job-services'
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



    def getEpochs(self, fabricName, pcv = False):
        #Get all the epochs (sorted from oldest to new from a fabric. ToDo Add filter support based on times
        # By default I drop all the epoch of type Pre Change Verification. 

        fabric = self.getAG(fabricName)            
        url =  u'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+str(fabric['uuid'])+'/epochs?$sort=collectionTimestamp'
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
            elif '4.1' in self.version:
                return [i for i in req.json()['value']['data'] if not (i['epoch_type'] == 'PCV')]


    def getAllReqSets(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirement-sets'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']

    def getAllReq(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/requirements'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']

    def getAllTrafficSelectors(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/traffic-selectors'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']

    def getAllObjSelectors(self):
        # Need to get an Assurange gropup to access requirement sets so I get the first one. 
        ag = self.getFirstAG()
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag["uuid"]+'/model/aci-policy/compliance-requirement/object-selectors'
        req = requests.get(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        return req.json()['value']['data']


    def deleteAG(self, obj):
        url = u'https://'+self.ip_addr+'/api/v1/config-services/assured-networks/aci-fabric/' + obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Assurance group %s", obj['unique_name'])
        else:
            self.logger.info("Deleting Assurance group %s failed with error %s",obj['unique_name'], req.json())

    def deleteReqSet(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/requirement-sets/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Requirement Set %s", obj['name'])
        else:
            self.logger.info("Deleting Requirement Set %s failed with error %s",obj['name'], req.json())

    def deleteReq(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/requirements/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Requirement %s", obj['name'])
        else:
            self.logger.info("Deleting Requirement %s failed with error %s",obj['name'], req.json())

    def deleteObjSelector(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/object-selectors/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted Object Selector %s", obj['name'])
        else:
            self.logger.info("Deleting Object Selector %s failed with error %s",obj['name'], req.json())

    def deleteTrafficSelector(self, ag_uuid, obj):
        url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/'+ag_uuid+'/model/aci-policy/compliance-requirement/traffic-selectors/'+obj['uuid']
        req = requests.delete(url, headers=self.http_headers, cookies=self.session_cookie, verify=False)
        if req.status_code == 200:
            self.logger.info("Deleted traffic-selector %s", obj['name'])
        else:
            self.logger.info("Deleting traffic-selector %s failed with error %s",obj['name'], req.json())

    def createPreChange(self, ag_name, name, config):
        url = 'https://'+self.ip_addr+'/api/v1/config-services/prechange-analysis'
        fabric_id = str(self.getAG(ag_name)['uuid'])
        latest_epoch = self.getEpochs(ag_name)[-1]['epoch_id']
        fields = {
                
                # The name of the file upload field... Not the file name                
                ('data', 
                    # This would be the name of the file. None because I am not passing a file 
                    (None,
                       
                        # content to upload 
                            '''{
                                  "name": "''' + name + '''",
                                  "fabric_uuid": "''' + fabric_id + '''",
                                  "base_epoch_id": "''' + latest_epoch + '''",
                                  
                                  "changes": [
                                    ''' + config + '''
                                  ],
                                  "stop_analysis": false,
                                  "change_type": "CHANGE_LIST"
                                }'''
                         # The content type of the file
                        , 'application/json'))
                  }

        m = MultipartEncoder(fields=fields)
        #Replace the normal 'Content-Type':'application/json;charset=utf-8' with the multipart/form-data and the boundary 
        h = self.http_headers
        h['Content-Type']= m.content_type
        req = requests.post(url, data=m,  headers=h, cookies=self.session_cookie, verify=False) 
        if req.status_code == 200:
            self.logger.info("Created PreChange Job")
        else:
            self.logger.info("Error %s", req.content)

    def getPreChangeResult(self,name):
        pass    

    def getTcamStats(self,ag_name):
        fabric_id = str(self.getAG(ag_name)['uuid'])
        latest_epoch = self.getEpochs(ag_name)[-1]['epoch_id']
        self.logger.debug("last epoch id is %s", latest_epoch)
        page = 0
        objPerPage=200
        has_more_data = True
        tcam_data = []
        # As long as there is more data get it
        while has_more_data:  
            self.logger.info("Requesting %d objects per page", objPerPage)            
            #I get data sorter by tcam hists for hitcount-by-rules --> hitcount-by-epgpair-contract-filter
            url = 'https://'+self.ip_addr+'/api/v1/event-services/assured-networks/' + fabric_id +'/model/aci-policy/tcam/hitcount-by-rules/hitcount-by-epgpair-contract-filter?$epoch_id='+latest_epoch+'&$page='+str(page)+'&$size='+str(objPerPage)+'&$sort=-cumulative_count&$view=histogram'
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

