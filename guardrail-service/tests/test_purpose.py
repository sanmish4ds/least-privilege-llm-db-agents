import sqlite3

import pytest

from guardrail.purpose import PurposeMonitor, PurposePolicy, analyze, violations

SCHEMA = {"customer": {"c_custkey": "int", "c_name": "text", "c_phone": "text",
                       "c_acctbal": "real", "c_seg": "text"}}


def policy(**kw) -> PurposePolicy:
    return PurposePolicy.model_validate({
        "schema": SCHEMA,
        "entities": {"customer": "c_custkey"},
        "sensitivity": {"customer.c_phone": 1.0, "customer.c_acctbal": 0.8},
        "purposes": {
            "finance": {"columns": {"customer.c_acctbal": "agg", "customer.c_seg": "raw",
                                    "customer.c_custkey": "filter"}},
            "support": {"columns": {"customer.c_custkey": "raw", "customer.c_name": "raw",
                                    "customer.c_phone": "raw"},
                        "entity_budget": {"customer": 2}},
        },
        **kw,
    })


@pytest.fixture
def run():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE customer(c_custkey INT, c_name TEXT, c_phone TEXT, c_acctbal REAL, c_seg TEXT)")
    con.executemany("INSERT INTO customer VALUES (?,?,?,?,?)",
                    [(k, f"C{k}", f"555-{k:04d}", 100.0 * k, "A" if k <= 10 else "B") for k in range(1, 21)])
    return lambda sql: con.execute(sql).fetchall()


def test_analyze_modes():
    q = analyze("SELECT c.c_seg, AVG(c.c_acctbal) FROM customer c WHERE c.c_custkey > 3 GROUP BY c.c_seg", policy())
    assert q.uses == {"customer.c_seg": "raw", "customer.c_acctbal": "agg", "customer.c_custkey": "filter"}


def test_subquery_projection_is_filter_use():
    q = analyze("SELECT COUNT(*) FROM customer WHERE c_custkey IN (SELECT c_custkey FROM customer WHERE c_seg = 'A')",
                policy())
    assert q.uses["customer.c_custkey"] == "filter"


def test_violation_weights():
    p = policy()
    v = violations(analyze("SELECT c_acctbal, c_phone FROM customer", p), p.purposes["finance"], p)
    assert v == {"customer.c_acctbal:raw": 0.8, "customer.c_phone:raw": 1.0}


def test_session_drift_counts_each_violation_once():
    m = PurposeMonitor(policy(), "finance")
    for _ in range(5):
        s = m.check("SELECT c_name FROM customer LIMIT 1")
    assert s.drift_q == pytest.approx(0.1) and s.drift == pytest.approx(0.1)


def test_small_cell_and_tracker(run):
    m = PurposeMonitor(policy(), "finance", executor=run)
    assert m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_seg = 'A'").cell == pytest.approx(0.1)
    s = m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_seg = 'A' AND c_custkey <> 4")
    assert s.cell_q == pytest.approx(1 / 9)          # each query alone looks fine
    assert s.cell == 1.0                             # together they isolate customer 4


def test_grouped_small_cell(run):
    m = PurposeMonitor(policy(), "finance", executor=run)
    assert m.check("SELECT c_custkey, AVG(c_acctbal) FROM customer GROUP BY c_custkey").cell_q == 1.0


def test_audit_mode_refuses_completing_query_only(run):
    m = PurposeMonitor(policy(min_isolation=3), "finance", executor=run)
    assert not m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_seg = 'A'").refuse
    assert m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_seg = 'A' AND c_custkey <> 4").refuse
    assert not m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_seg = 'B'").refuse


def test_breadth_over_budget(run):
    m = PurposeMonitor(policy(), "support", executor=run)
    for k in (1, 2):
        s = m.check(f"SELECT c_name, c_phone FROM customer WHERE c_custkey = {k}")
    assert s.breadth == 1.0 and not s.violations
    s = m.check("SELECT c_name, c_phone FROM customer WHERE c_custkey = 3")
    assert s.breadth == 1.5 and any("budget 2" in r for r in s.reasons)


def test_no_executor_keeps_data_signals_off():
    s = PurposeMonitor(policy(), "finance").check("SELECT AVG(c_acctbal) FROM customer WHERE c_custkey = 1")
    assert s.cell == 0.0 and s.breadth == 0.0


def test_count_is_filter_and_projected_max_is_raw():
    q = analyze("SELECT COUNT(c_name), MAX(c_acctbal) FROM customer WHERE c_seg IN "
                "(SELECT c_seg FROM customer GROUP BY c_seg HAVING MAX(c_acctbal) > 5)", policy())
    assert q.uses == {"customer.c_name": "filter", "customer.c_acctbal": "raw", "customer.c_seg": "filter"}


def test_linear_audit_catches_three_query_differencing(run):
    seq = ["SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN 1 AND 6",
           "SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN 7 AND 12",
           "SELECT SUM(c_acctbal) FROM customer WHERE c_custkey BETWEEN 2 AND 12"]
    pairwise = PurposeMonitor(policy(min_isolation=2), "finance", executor=run)
    assert not any(pairwise.check(q).refuse for q in seq)       # no nested pair differs by < 2
    linear = PurposeMonitor(policy(min_isolation=2, linear_audit=True), "finance", executor=run)
    assert [linear.check(q).refuse for q in seq] == [False, False, True]   # 1 = q1 + q2 - q3


def test_strict_mode_refuses_predicates_on_protected_columns(run):
    m = PurposeMonitor(policy(min_isolation=2, strict_protected=True), "finance", executor=run)
    assert m.check("SELECT c_seg, AVG(c_acctbal) FROM customer GROUP BY c_seg").refuse is False
    s = m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_acctbal > 500")
    assert s.refuse and "c_acctbal" in s.reasons[-1]


def test_entity_budget_enforcement_refuses_and_keeps_state(run):
    m = PurposeMonitor(policy(enforce_entity_budget=True), "support", executor=run)
    assert not m.check("SELECT c_name, c_phone FROM customer WHERE c_custkey IN (1, 2)").refuse
    s = m.check("SELECT c_name, c_phone FROM customer WHERE c_custkey = 3")
    assert s.refuse and s.breadth == 1.0                       # refused query adds nothing
    assert not m.check("SELECT c_name, c_phone FROM customer WHERE c_custkey = 2").refuse


def test_fail_closed_refuses_protected_column_inside_cte_or_derived_table(run):
    m = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=run)
    for sql in ["WITH t AS (SELECT c_acctbal AS b FROM customer WHERE c_custkey = 4) SELECT SUM(b) FROM t",
                "SELECT SUM(b) FROM (SELECT c_acctbal AS b FROM customer WHERE c_custkey = 4) AS t",
                "SELECT SUM(c_acctbal) FROM customer WHERE c_custkey < 5 UNION SELECT SUM(c_acctbal) FROM customer"]:
        s = m.check(sql)
        assert s.refuse and "cannot be audited" in s.reasons[-1], sql
    assert not m.check("SELECT c_seg, COUNT(*) FROM (SELECT c_seg FROM customer) AS t GROUP BY c_seg").refuse


def test_fail_closed_distinguishes_empty_result_from_failed_rewrite(run):
    m = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=run)
    assert not m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_custkey > 1000").refuse   # no entity matched

    def broken(sql):
        raise RuntimeError("rewrite failed")
    m2 = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=broken)
    s = m2.check("SELECT AVG(c_acctbal) FROM customer WHERE c_seg = 'A'")
    assert s.refuse and "could not be computed" in s.reasons[-1]


def test_predicate_audit_blocks_count_binary_search(run):
    """COUNT ... WHERE key = i AND balance > x recovers balance i by bisection unless audited."""
    probe = "SELECT COUNT(*) FROM customer WHERE c_custkey = 7 AND c_acctbal > {}"
    off = PurposeMonitor(policy(min_isolation=3, linear_audit=True, audit_predicates=False), "finance",
                         executor=run)
    assert not any(off.check(probe.format(x)).refuse for x in (500, 750, 625))
    on = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=run)
    s = on.check(probe.format(500))
    assert s.refuse and "predicate on customer.c_acctbal" in s.reasons[-1]


def test_predicate_audit_allows_bands_over_large_groups(run):
    m = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=run)
    for lo, hi in ((0, 500), (500, 1000), (1000, 2500)):     # histogram bands per segment
        sql = f"SELECT c_seg, COUNT(*) FROM customer WHERE c_acctbal BETWEEN {lo} AND {hi} GROUP BY c_seg"
        assert not m.check(sql).refuse, sql
    assert not m.check("SELECT AVG(c_acctbal) FROM customer WHERE c_seg = 'A' AND c_acctbal > 0").refuse


def test_predicate_audit_catches_differencing_and_linear_combinations(run):
    m = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=run)
    q = "SELECT COUNT(*) FROM customer WHERE c_custkey BETWEEN {} AND {} AND c_acctbal > 700"
    assert not m.check(q.format(1, 10)).refuse
    assert m.check(q.format(1, 9)).refuse                      # nested, differs by one entity
    m2 = PurposeMonitor(policy(min_isolation=2, linear_audit=True), "finance", executor=run)
    seq = [q.format(1, 6), q.format(7, 12), q.format(2, 12)]   # 1 = q1 + q2 - q3, no small nested pair
    assert [m2.check(x).refuse for x in seq] == [False, False, True]


def test_predicate_audit_refuses_unrelaxable_shapes_and_row_queries(run):
    m = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=run)
    for sql in ["SELECT COUNT(*) FROM customer WHERE c_custkey < 10 AND NOT c_acctbal > 500",
                "SELECT c_seg, COUNT(*) FROM customer GROUP BY c_seg, c_acctbal",
                "SELECT c_seg FROM customer WHERE c_custkey < 10 ORDER BY c_acctbal LIMIT 1",
                "SELECT MAX(c_seg) FROM customer WHERE c_custkey < 10 AND c_acctbal > 500",   # weighted / one-row
                "SELECT c_seg FROM customer WHERE c_custkey < 10 AND c_acctbal > 500"]:   # one row per entity
        assert m.check(sql).refuse, sql


def test_refused_predicate_query_leaves_state_unchanged(run):
    m = PurposeMonitor(policy(min_isolation=3, linear_audit=True), "finance", executor=run)
    assert m.check("SELECT COUNT(*) FROM customer WHERE c_custkey = 7 AND c_acctbal > 1").refuse
    assert not any(m.pred_sets.values()) and not m.check(
        "SELECT COUNT(*) FROM customer WHERE c_custkey BETWEEN 1 AND 10 AND c_acctbal > 1").refuse


# ---- joins: an entity joined to several rows enters an answer with that multiplicity ----

JSCHEMA = {"customer": {"c_custkey": "int", "c_acctbal": "real", "c_seg": "text"},
           "orders": {"o_orderkey": "int", "o_custkey": "int", "o_month": "int"}}


def jpolicy(**kw) -> PurposePolicy:
    return PurposePolicy.model_validate({
        "schema": JSCHEMA, "entities": {"customer": "c_custkey"},
        "sensitivity": {"customer.c_acctbal": 0.8},
        "purposes": {"finance": {"columns": {
            "customer.c_acctbal": "agg", "customer.c_seg": "raw", "customer.c_custkey": "filter",
            "orders.o_orderkey": "filter", "orders.o_custkey": "filter", "orders.o_month": "raw"}}},
        "min_isolation": 3, **kw})


@pytest.fixture
def jrun():
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE customer(c_custkey INT, c_acctbal REAL, c_seg TEXT)")
    con.execute("CREATE TABLE orders(o_orderkey INT, o_custkey INT, o_month INT)")
    con.executemany("INSERT INTO customer VALUES (?,?,?)", [(k, 100.0 * k, "A") for k in range(1, 7)])
    # customer 1 has three orders in month 1; customers 2 and 3 one each
    con.executemany("INSERT INTO orders VALUES (?,?,?)",
                    [(1, 1, 1), (2, 1, 1), (3, 1, 1), (4, 2, 1), (5, 3, 1), (6, 4, 2), (7, 5, 2), (8, 6, 2)])
    return lambda sql: con.execute(sql).fetchall()


JOINED = ("SELECT SUM(c.c_acctbal) FROM customer c JOIN orders o ON o.o_custkey = c.c_custkey "
          "WHERE o.o_month = 1")
PLAIN = "SELECT SUM(c_acctbal) FROM customer WHERE c_custkey IN (1, 2, 3)"


@pytest.mark.parametrize("linear", [False, True])
def test_join_weighted_sums_are_audited_with_their_multiplicities(jrun, linear):
    # weights (3,1,1) and (1,1,1): their difference is 2 * x_1, one customer's balance
    m = PurposeMonitor(jpolicy(linear_audit=linear), "finance", executor=jrun)
    assert not m.check(JOINED).refuse
    sig = m.check(PLAIN)
    assert sig.refuse, sig.reasons


def test_join_weighted_sums_refused_in_strict_mode(jrun):
    m = PurposeMonitor(jpolicy(linear_audit=True, strict_protected=True), "finance", executor=jrun)
    assert not m.check(PLAIN).refuse
    assert m.check(JOINED).refuse


def test_weighted_count_under_threshold_refused_distinct_count_allowed(jrun):
    m = PurposeMonitor(jpolicy(linear_audit=True), "finance", executor=jrun)
    probe = ("SELECT COUNT(*) FROM customer c JOIN orders o ON o.o_custkey = c.c_custkey "
             "WHERE o.o_month = 1 AND c.c_acctbal > 50")
    sig = m.check(probe)
    assert sig.refuse and "unequally" in sig.reasons[-1]
    ok = probe.replace("COUNT(*)", "COUNT(DISTINCT c.c_custkey)")
    assert not m.check(ok).refuse


@pytest.mark.parametrize("sql", [
    "SELECT SUM(c_acctbal * 2) FROM customer",
    "SELECT SUM(DISTINCT c_acctbal) FROM customer",
    "SELECT AVG(CASE WHEN c_seg = 'A' THEN c_acctbal ELSE 0 END) FROM customer",
])
def test_aggregate_of_an_expression_of_the_protected_column_refused(jrun, sql):
    sig = PurposeMonitor(jpolicy(linear_audit=True), "finance", executor=jrun).check(sql)
    assert sig.refuse, sig.reasons
