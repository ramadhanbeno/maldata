import csv
import pandas as pd

ff = pd.read_csv('datasetmalware.csv', sep='|')
pd.set_option("display.max_columns", None)

df = pd.DataFrame(ff)
df

df.to_csv('maldata.csv', index=False)
