import sys, sqlite3, yaml
sys.path.insert(0,"guardrail-service"); sys.path.insert(0,"experiments/purpose_sql")
from guardrail.purpose import PurposePolicy, PurposeMonitor, analyze, violations
from tpch_db import SCHEMA
raw=yaml.safe_load(open("experiments/purpose_sql/purpose_policy.yaml")); raw["schema"]=SCHEMA
raw.update(min_isolation=3, linear_audit=True, enforce_entity_budget=True)
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

n,seg=18,'FURNITURE'
G=f"c_nationkey={n} AND c_mktsegment='{seg}'"
mon=PurposeMonitor(pol,"finance_analytics",executor=run)

months=[f"{y}-{m:02d}-01" for y in range(1992,1999) for m in range(1,13)]
found=None
for a in range(len(months)):
    for b in range(a+1,len(months)):
        W=f"{G} AND o_orderdate >= '{months[a]}' AND o_orderdate < '{months[b]}'"
        w=dict(run(f"SELECT c_custkey, COUNT(*) FROM customer JOIN orders ON o_custkey=c_custkey WHERE {W} GROUP BY c_custkey"))
        if len(w)>=3 and T in w and w[T] > sum(v for k,v in w.items() if k!=T):
            found=(W,w); break
    if found: break
W,w=found; print("window weights",w)
lo,hi=-1000.0,10000.0; nq=ref=0
while hi-lo>0.005:
    t=round((lo+hi)/2,3)
    s2=f"SELECT COUNT(*) FROM customer JOIN orders ON o_custkey=c_custkey WHERE {W} AND c_acctbal > {t}"
    q=analyze(s2,pol); v=violations(q,spec,pol); sig=mon.check(s2); nq+=1
    if v or sig.refuse: ref+=1; print("refused",v,sig.reasons); break
    c=run(s2)[0][0]
    if c>=w[T]: lo=t
    else: hi=t
print("probes",nq,"refused",ref,"interval",lo,hi,"truth",truth)
