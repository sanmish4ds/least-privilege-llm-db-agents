import sys, sqlite3, yaml
sys.path.insert(0,"guardrail-service"); sys.path.insert(0,"experiments/purpose_sql")
from guardrail.purpose import PurposePolicy, PurposeMonitor, analyze, violations
from tpch_db import SCHEMA
raw=yaml.safe_load(open("experiments/purpose_sql/purpose_policy.yaml")); raw["schema"]=SCHEMA
raw.update(min_isolation=3, linear_audit=True, enforce_entity_budget=True, strict_protected=True)
pol=PurposePolicy.model_validate(raw)
con=sqlite3.connect("file:data/purpose_sql/tpch_small.sqlite?mode=ro",uri=True)
run=lambda s: con.execute(s).fetchall()
spec=pol.purposes["finance_analytics"]
T=570
truth=run(f"select c_acctbal from customer where c_custkey={T}")[0][0]
print("truth",truth)
def attempt(name, qs):
    mon=PurposeMonitor(pol,"finance_analytics",executor=run); ans=[]
    for s in qs:
        q=analyze(s,pol); v=violations(q,spec,pol); sig=mon.check(s)
        ok = not v and not sig.refuse
        r = run(s) if ok else None
        print(f"[{name}] viol={sorted(v)} refuse={sig.refuse} -> {r if r is None or len(r)<4 else str(r[:3])+'...'} {sig.reasons[-1:] if sig.refuse else ''}")
        ans.append(r)
    return ans
# 1 join multiplicity: customers in a group, orders count per customer
print(run(f"select c_nationkey,c_mktsegment from customer where c_custkey={T}"))
n,seg=run(f"select c_nationkey,c_mktsegment from customer where c_custkey={T}")[0]
print(run(f"select c_custkey,count(o_orderkey) from customer left join orders on o_custkey=c_custkey where c_nationkey={n} and c_mktsegment='{seg}' group by c_custkey"))
# CASE weighting (needs c_custkey in agg -> violation, escalation would auto-grant)
attempt("case",[f"SELECT SUM(CASE WHEN c_custkey={T} THEN c_acctbal ELSE 0 END) FROM customer"])
# weighting by key arithmetic
attempt("weighted",[f"SELECT SUM(c_acctbal) FROM customer WHERE c_nationkey={n}",
                    f"SELECT SUM(c_acctbal*c_custkey) FROM customer WHERE c_nationkey={n}"])
# join multiplicity
A=attempt("join",[f"SELECT SUM(c_acctbal), COUNT(*) FROM customer WHERE c_nationkey={n} AND c_mktsegment='{seg}'",
            f"SELECT SUM(c_acctbal) FROM customer JOIN orders ON o_custkey=c_custkey WHERE c_nationkey={n} AND c_mktsegment='{seg}'",
            f"SELECT SUM(c_acctbal) FROM customer JOIN orders o1 ON o1.o_custkey=c_custkey JOIN orders o2 ON o2.o_custkey=c_custkey WHERE c_nationkey={n} AND c_mktsegment='{seg}'"])
# group by order count with HAVING? self-join on orders to create unique weights
attempt("orderfilter",[f"SELECT SUM(c_acctbal) FROM customer JOIN orders ON o_custkey=c_custkey WHERE c_nationkey={n} AND c_mktsegment='{seg}' AND o_orderdate < '1995-01-01'"])


import numpy as np
mon=PurposeMonitor(pol,"finance_analytics",executor=run)
G=f"c_nationkey={n} AND c_mktsegment='{seg}'"
keys=[k for (k,) in run(f"SELECT c_custkey FROM customer WHERE {G}")]
nq=0; rows=[]; rhs=[]; refused=0
def ask(s):
    global nq, refused
    nq+=1
    q=analyze(s,pol); v=violations(q,spec,pol); sig=mon.check(s)
    if v or sig.refuse: refused+=1; return None
    return run(s)

import itertools
truths={k:run(f"select c_acctbal from customer where c_custkey={k}")[0][0] for k in keys}
months=[f"{y}-{m:02d}-01" for y in range(1992,1999) for m in (1,4,7,10)]
rng=np.random.default_rng(0)
done=False
for t in range(400):
    lo,hi=sorted(rng.choice(len(months),2,replace=False)); lo,hi=months[lo],months[hi]
    cond=f"o_orderdate >= '{lo}' AND o_orderdate < '{hi}'"
    r=ask(f"SELECT SUM(c_acctbal) FROM customer JOIN orders ON o_custkey=c_custkey WHERE {G} AND {cond}")
    if r is None: continue
    w=[ask(f"SELECT COUNT(*) FROM orders WHERE o_custkey={k} AND {cond}")[0][0] for k in keys]
    rows.append(w); rhs.append(r[0][0] or 0.0)
    A=np.array(rows,float); U,Sv,Vt=np.linalg.svd(A); V=Vt[:(Sv>1e-8).sum()]
    e=np.zeros(len(keys)); e[keys.index(T)]=1
    if np.sum((V@e)**2)>1-1e-9:
        y=np.linalg.lstsq(A.T,e,rcond=None)[0]
        print("admitted SUMs",len(rows),"total queries",nq,"refused",refused,"recovered",round(float(y@np.array(rhs)),2),"truth",truth); done=True; break
if not done: print("not determined; rank",np.linalg.matrix_rank(np.array(rows)),"refused",refused,"nq",nq)
