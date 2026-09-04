"""Stylometry baseline: predicts author/class from writing style, not identity certainty.
Train only on legally obtained, properly authorized text. Synthetic demo data can be used for SIH.
"""
import pandas as pd, joblib, os
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

df=pd.read_csv('stylometry_demo.csv')
Xtr,Xte,ytr,yte=train_test_split(df.text,df.author,test_size=.25,random_state=42,stratify=df.author)
model=Pipeline([('tfidf',TfidfVectorizer(analyzer='char',ngram_range=(3,5),min_df=1,max_features=20000)),('clf',LogisticRegression(max_iter=2000))])
model.fit(Xtr,ytr)
print(classification_report(yte,model.predict(Xte)))
os.makedirs('models',exist_ok=True);joblib.dump(model,'models/stylometry.joblib')
