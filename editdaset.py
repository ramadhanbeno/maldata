import pandas as pd

ff = pd.read_csv('Output_CSV/rawPE.csv', sep=',')
pd.set_option("display.max_columns", None)

df = pd.DataFrame(ff)

df.to_csv('Output_clean_CSV/PE++++.csv', index=False)
