import json
import os


directory = '/home/x/ta/dataset/cname/'

for ffile in os.listdir(directory):
    ff = '/home/x/ta/dataset/cname/'+ffile
    file_json = open(ff)
    data = json.load(file_json)
    new_name = data['target']['file']['name']
    c_name = '/home/x/ta/dataset/cname/' + new_name
    print(new_name)
    os.rename(ff, c_name)


