import csv, random, os
random.seed(42)
os.makedirs('data',exist_ok=True)
names=['Amit Verma','Ravi Kumar','Sahil Khan','Neha Sharma','Pooja Singh','Vikram Rao','Imran Ali','Karan Mehta','Rohan Das','Priya Gupta']
orgs=['Northline Logistics','Shakti Traders','Metro Imports','Apex Finance']
rows=[]
for i in range(250):
    a,b=random.sample(range(len(names)),2)
    same_org=random.random()<0.35
    shared_location=random.random()<0.45
    shared_phone=random.random()<0.12
    relation=int(same_org*0.35+shared_location*0.25+shared_phone*0.45+random.random()*0.15>0.5)
    rows.append([names[a],names[b],int(same_org),int(shared_location),int(shared_phone),random.randint(1,20),relation])
with open('data/relationship_pairs.csv','w',newline='',encoding='utf8') as f:
    w=csv.writer(f); w.writerow(['person_a','person_b','same_org','shared_location','shared_phone','co_occurrences','label']); w.writerows(rows)
