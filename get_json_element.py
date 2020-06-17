import json
import pandas as pd
import numpy as np
import os

def get_api(fname):
    file_json = open(fname)
    data = json.load(file_json)
    apicall = data['behavior']['apistats']
    list_api = []
    for x in apicall:
        for y in apicall[x]:
            list_api.append([y,apicall[x][y]])
    a = np.array(list_api)
    data = a
    dataset = pd.DataFrame({'Api': data[:,0], 'Return': data[:,1]})
    pd.set_option("display.max_rows", None)
    df = dataset.drop_duplicates(subset='Api', keep='first')
    df
    return df

def select_api(data):

def extract_info(fpath):
    api = []
    api.append(get_api(fpath))
    return api
# a = np.array(list_api)
# data = a
# dataset = pd.DataFrame({'Api': data[:,0], 'Return': data[:,1]})
# # pd.set_option("display.max_rows", None)
# df = dataset.drop_duplicates(subset='Api', keep='first')
# print(df)
#
# # LIST 100 API
# print(df[df.Api == "RegCloseKey"].Return.item())
# print(df[df.Api == "LdrUnloadDll"].Return.item())

#

# read
if __name__ == '__main__':
    output = "Output_CSV/json.csv"
    csv_delimiter = ","
    columns = [
        "Name",
        "Md5",
    ]

    ff = open(output, "a")
    ff.write(csv_delimiter.join(columns) + "\n")
    for ffile in os.listdir('/home/x/ta/dataset/report json'):
        print(ffile)
        try:
            api = extract_info(os.path.join('/home/x/ta/dataset/report json', ffile))
        #     api.append(1)
            ff.write(csv_delimiter.join(map(lambda x: str(x), api)) + "\n")
        except:
            print('\t -> Bad json format')

    ff.close()
