#Convert TCAM Stats from JSON to CSV
import json
from pprint import pprint
import csv
import argparse

def get_args():
    parser = argparse.ArgumentParser(description="Script to convert JSON Contract Data to CSV")
    parser.add_argument('-i', dest='inputFile', help='Json TCAM Stats data input file',required=True)
    args = parser.parse_args()
    return args


args= get_args()

with open(args.inputFile, 'r') as f: tcam_data = json.load(f) 

tcam_stats = []

for page in tcam_data:
    for item in page:
        tdic = {}
        for key, value in item.items():
            if key == "bucket":
                tdic['Provider EPG'] = value['provider_epg']['dn'].replace("uni/","")
                tdic['Consumer VRF'] = value['consumer_vrf']['dn'].replace("uni/","")
                tdic['Consumer EPG'] = value['consumer_epg']['dn'].replace("uni/","")
                tdic['Contract'] = value['contract']['dn'].replace("uni/","")
                tdic['Filter'] =  value['filter']['dn'].replace("uni/","")
            if key == "output":
                tdic["Month Hit Count"] = value['month_count']
                tdic['Total Hits'] =  value['cumulative_count']
                tdic['TCAM Usage'] = value['tcam_entry_count']
        tcam_stats.append(tdic)

outFileName = args.inputFile.split('.')[0] + '.csv' 
with open(outFileName, 'w', newline='') as file:
    fieldnames = ['Provider EPG', 'Consumer EPG', 'Consumer VRF','Contract','Filter','Montly Hits', 'Total Hits','TCAM Usage']
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    for i in tcam_stats:
        writer.writerow(i)

