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
    arr = df.values
    arr
    return arr

def extract_info(fpath):
    api = []
    api.append(os.path.basename(fpath))
    features = get_api(fpath)
    select_api = pd.DataFrame({'Api': features[:,0], 'Return': features[:,1]})
    # print(len(select_api))
    if (len(select_api)>100):
        api_h = select_api[:100]
        # api.append(api_h)
        for row in api_h.itertuples():
            api.append(row.Return)
    else:
        for row in select_api.itertuples():
            api.append(row.Return)
        xx = 100 - len(select_api)
        for i in range(xx):
            api.append("0")

    return api

if __name__ == '__main__':
    output = "Output_CSV/json.csv"
    csv_delimiter = ","
    columns = []
    columns.append("Name")
    for i in range(100):
        aaa = ("T%d"%(i+1))
        columns.append(aaa)
    columns.append("Label")

    ff = open(output, "a")
    ff.write(csv_delimiter.join(columns) + "\n")
    for ffile in os.listdir('/home/x/ta/dataset/report_json/goodware'):
        print(ffile)
        try:
            api = extract_info(os.path.join('/home/x/ta/dataset/report_json/goodware', ffile))
            api.append(1)
            ff.write(csv_delimiter.join(map(lambda x: str(x), api)) + "\n")
        except:
            print('\t -> Bad json format')

    for ffile in os.listdir('/home/x/ta/dataset/report_json/malware'):
        print(ffile)
        try:
            api = extract_info(os.path.join('/home/x/ta/dataset/report_json/malware', ffile))
            api.append(0)
            ff.write(csv_delimiter.join(map(lambda x: str(x), api)) + "\n")
        except:
            print('\t -> Bad json format')

    ff.close()
