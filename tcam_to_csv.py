#Convert TCAM Stats from JSON to CSV
import json
from pprint import pprint
import csv

with open('Tcam.json', 'r') as f: tcam_data = json.load(f) 

tcam_stats = []

for page in tcam_data:
    for item in page:
        tdic = {}
        for key, value in item.items():
            if key == "bucket":
                tdic['Provider EPG'] = value['provider_epg']['dn'].replace("uni/","")
                tdic['Consumer VRF'] = value['consumer_vrf']['dn'].replace("uni/","")
                tdic['Consumer EPG'] = value['consumer_epg']['name']
                tdic['Contract'] = value['contract']['dn'].replace("uni/","")
                tdic['Filter'] =  value['filter']['dn'].replace("uni/","")
            if key == "output":
                tdic['Hits'] =  value['cumulative_count']
                tdic['TCAM Usage'] = value['tcam_entry_count']
        tcam_stats.append(tdic)
with open('tcam_stats.csv', 'w', newline='') as file:
    fieldnames = ['Provider EPG', 'Consumer EPG', 'Consumer VRF','Contract','Filter','Hits','TCAM Usage']
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    for i in tcam_stats:
        writer.writerow(i)
