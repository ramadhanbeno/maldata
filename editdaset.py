import csv
import pandas as pd

ff = pd.read_csv('data.csv', sep='|')
pd.set_option("display.max_columns", None)

df = pd.DataFrame(ff)
df

df.to_csv('maldata2.csv', index=False)

