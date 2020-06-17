import csv
import pandas as pd

ff = pd.read_csv('Output_CSV/dataset--1.csv', sep='|')
pd.set_option("display.max_columns", None)

df = pd.DataFrame(ff)
df

df.to_csv('maldata1300.csv', index=False)

