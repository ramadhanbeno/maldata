import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split

mal_df = pd.read_csv('maldata.csv')
pd.set_option("display.max_columns", None)
print(mal_df.columns)
print(mal_df.dtypes)
mal_df.drop(['Name', 'md5'], axis=1)
print('nilai missing value', mal_df.isna().values.any())
print('nilai duplikat', mal_df.duplicated().value_counts())

print('shape data sebelum di cleaning', mal_df.shape)
mal_df = mal_df.dropna()
print('shape data setelah di cleaning', mal_df.shape)
print(mal_df.corr())
#print(sns.heatmap(data=mal_df.corr()))
#plt.show()

# prediksi
y = mal_df['legitimate']

features = ['SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics']
X = mal_df[features]
print(X.describe())

# training menggunakan decisiontree regresor
mal_model = DecisionTreeRegressor(random_state=1)
print(mal_model.fit(X, y))
print(mal_model.predict(X.head()))
print(y.head())

y_hat = mal_model.predict(X)
print(mean_absolute_error(y, y_hat))

# training dan testing menggunakan model_selection
X_train, X_test, y_train, y_test = train_test_split(X, y, random_state= 1)
mal_model = DecisionTreeRegressor(random_state=1)
print(mal_model.fit(X_train, y_train))
y_hat = mal_model.predict(X_test)
print(mean_absolute_error(y_test, y_hat))




