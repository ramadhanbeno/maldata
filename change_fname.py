import json
import os

for ffile in os.listdir('/home/x/ta/dataset/report_json/malware'):
    try:
        ff = '/home/x/ta/dataset/report_json/malware/'+ffile
        file_json1 = open(ff)
        data1 = json.load(file_json1)
        new_name1 = data1['target']['file']['name']
        c_name1 = '/home/x/ta/dataset/report_json/malware/' + new_name1 + '.json'
        print(new_name1)
        os.rename(ff, c_name1)
    except:
        print("error change name")

for fffile in os.listdir('/home/x/ta/dataset/report_json/goodware'):
    try:
        ff2 = '/home/x/ta/dataset/report_json/goodware/'+ fffile
        file_json2 = open(ff2)
        data2 = json.load(file_json2)
        new_name2 = data2['target']['file']['name']
        c_name = '/home/x/ta/dataset/report_json/goodware/' + new_name2 + '.json'
        print(new_name2)
        os.rename(ff2, c_name)
    except:
        print("error change name")


