from prettytable import PrettyTable
from prettytable import MSWORD_FRIENDLY
import json
from datetime import datetime

GREEN = '\033[32m' # Green
CYAN =  '\033[36m' # Cyan Text
RED =  '\033[31m' # Red Text
PURPLE =  '\033[35m' # Purple Text
YELLOW =  '\033[33m' # Yellow Text
BLUE =  '\033[34m' # Blue Text

ENDC = '\033[m'


class Parser:
    def __init__(self,obj):
        self.obj = obj
    
    def ParsePreChangeResults(self,response_later,response,pre_change_analysis_name,verbose_flag,table_response,early_epoch_id,later_epoch_id):
        epoch1_only_count = 0
        epoch2_only_count = 0
        both_epochs_count = 0
        epoch1_count = 0
        epoch2_count = 0
        for x in response.json()['value']['data']:
            TableOutput(x,table_response,early_epoch_id,later_epoch_id)
            for y in (x['output']):
                if(y['bucket'] == "EPOCH1_ONLY"):
                    epoch1_only_count += y['count']
                    print("Earlier Epoch Only: " + str(y['count']))
                if(y['bucket'] == "EPOCH2_ONLY"):
                    epoch2_only_count += y['count']
                    print("Later Epoch Only: " + str(y['count']))              
                if(y['bucket'] == "BOTH_EPOCHS"):
                    both_epochs_count += y['count']
                    print("Common: " + str(y['count']))
                if(y['bucket'] == "EPOCH1"):
                    epoch1_count += y['count']
                    print("Earlier Epoch: " + str(y['count']))
                if(y['bucket'] == "EPOCH2"):
                    epoch2_count += y['count']
                    print("Later Epoch: " + str(y['count']))    
        print("====================================")
        print("Totals:")
        print("Earlier Epoch Only: " + str(epoch1_only_count))
        print("Earlier Epoch: " + str(epoch1_count))
        print("Common: " + str(both_epochs_count))
        print("Later Epoch: " + str(epoch2_count))
        if(epoch2_only_count > 0):
            print(RED + "Later Epoch Only: " + str(epoch2_only_count), ENDC)
            print(RED + "Pre-change Analyis '" + pre_change_analysis_name + "' failed.", ENDC)
            for x in response_later.json()['value']['data']:
                createTable(x['epoch2_details']['severity'],response_later,early_epoch_id,later_epoch_id)
            print("====================================")
            return False
        print(GREEN + "Later Epoch Only: " + str(epoch2_only_count), ENDC)
        print(GREEN + "Pre-change Analyis '" + pre_change_analysis_name + "' passed.", ENDC)
        print("====================================")

        return True   

def TableOutput(x,table_response,early_epoch_id,later_epoch_id):
    if(x['bucket'] == "EVENT_SEVERITY_INFO"):
                print(GREEN + "----------------------------", ENDC)
                print(GREEN + "<-------- ✓ INFO ✓ -------->", ENDC)
                print(GREEN + "----------------------------", ENDC)
                severity = "EVENT_SEVERITY_INFO"
    if(x['bucket'] == "EVENT_SEVERITY_WARNING"):
                print(CYAN + "-------------------------------", ENDC)
                print(CYAN + "<-------- ! WARNING ! -------->", ENDC)
                print(CYAN + "-------------------------------", ENDC)
                severity = "EVENT_SEVERITY_WARNING"
    if(x['bucket'] == "EVENT_SEVERITY_MINOR"):
                print(YELLOW + "-------------------------------", ENDC)
                print(YELLOW + "<-------- !! MINOR !! -------->", ENDC)
                print(YELLOW + "-------------------------------", ENDC)
                severity = "EVENT_SEVERITY_MINOR"
    if(x['bucket'] == "EVENT_SEVERITY_MAJOR"):
                print(PURPLE + "-----------------------------", ENDC)
                print(PURPLE + "<-------- ⚠ MAJOR ⚠ -------->", ENDC)
                print(PURPLE + "-----------------------------", ENDC)
                severity = "EVENT_SEVERITY_MAJOR"
    if(x['bucket'] == "EVENT_SEVERITY_CRITICAL"):
                print(RED + "-----------------------------------", ENDC)               
                print(RED + "<-------- ⓧ  CRITICAL ⓧ  -------->", ENDC)
                print(RED + "-----------------------------------", ENDC)
                severity = "EVENT_SEVERITY_CRITICAL"   
    createTable(severity,table_response,early_epoch_id,later_epoch_id)



def createTable(severity,table_response,early_epoch_id,later_epoch_id):
    rows = []
    if(table_response):
        t = PrettyTable(['Epoch','Event Name','Severity','Event Category','Description'])
        for item in table_response.json()['value']['data']:
            for ele in item.values():
                if(isinstance(ele,dict)):
                    if(severity in ele.values()):
                        rows = []
                        flag = False
                        for v in ele.values():
                            if(v == later_epoch_id):
                                rows.append("Later Epoch")
                                flag = False
                                continue
                            if(v == early_epoch_id):
                                flag = True
                                continue
                            if(flag == True):
                                continue
                            rows.append(v)
                        if(rows):
                            t.add_row(rows)
                            t.align["Description"] = "l"
                            t.align["Epoch UUID"] = "l"
                            t.align["Event Name"] = "l"
        if(rows):
            print(t)

def getAnalyses(response):
    l = []
    t = PrettyTable(['Pre-Change Analysis Name','Basic Epoch','Status', 'Analysis Submission Time', 'Submitter ID', 'Description'])
    for x in response.json()['value']['data']:
        if 'description' not in x:
            x['description'] = ""
        del x['job_id']
        del x['fabric_uuid']
        del x['base_epoch_id']
        del x['base_epoch_collection_time_rfc3339']
        del x['pre_change_epoch_uuid']
        del x['analysis_schedule_id']
        del x['epoch_delta_job_id']
        del x['enable_download']
        del x['allow_unsupported_object_modification']
        del x['changes']      
        del x['change_type']
        del x['stop_analysis']        
        del x['submitter_domain']        
        l.append(x)

    rows = []
    for x in l:
        if(len(rows) != 0):
            t.add_row(rows)
        rows = []
        for k,v in x.items():
            if(k == 'base_epoch_collection_timestamp' or k == 'analysis_submission_time'):
                m = str(v)[:10]
                dt_object = datetime.fromtimestamp(int(m))
                v = dt_object
            rows.append(v)
    t.align["Pre-Change Analysis Name"] = "l"
    t.align["Description"] = "l"
    print(t)      
    return False


# name: Pass
# base_epoch_collection_timestamp: 1579657384000
# analysis_status: COMPLETED
# analysis_submission_time: 1580207422592
# submitter_name: Local : admin