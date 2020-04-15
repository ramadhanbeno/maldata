import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
from sklearn.preprocessing import MinMaxScaler

#matplotlib inline
from sklearn.cluster import KMeans
from sklearn import datasets

pes = pd.read_csv("pe_section_headers.csv")

pd.set_option("display.max_columns", None)
df = pes.drop(['hash', 'virtual_address', 'entropy', 'virtual_size'], axis=1)
x_array = np.array(df)
print(x_array)

# scaling data
scaler = MinMaxScaler()
x_scaled = scaler.fit_transform(x_array)
# print(x_scaled)

kmeans = KMeans(n_clusters=4).fit(x_scaled)
centroids = kmeans.cluster_centers_
print(centroids)

plt.scatter(x_scaled[:,0], x_scaled[:,1], c=kmeans.labels_.astype(float), s=50, alpha=0.5)
plt.scatter(centroids[:, 0], centroids[:, 1], c='red', s=50)
plt.show()