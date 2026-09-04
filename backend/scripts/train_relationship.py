import pandas as pd, joblib, os
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
p='data/relationship_pairs.csv'
df=pd.read_csv(p)
X=df[['same_org','shared_location','shared_phone','co_occurrences']]; y=df.label
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
m=LogisticRegression(max_iter=1000).fit(Xtr,ytr)
print(classification_report(yte,m.predict(Xte)))
os.makedirs('models',exist_ok=True); joblib.dump(m,'models/relationship_model.joblib')
