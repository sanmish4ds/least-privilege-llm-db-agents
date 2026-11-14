"""Purpose-anchored session monitor for SQL agents (research prototype).

Each session declares a purpose. A purpose lists the columns it may touch and
how: ``filter`` (WHERE / JOIN / GROUP BY only, or inside COUNT), ``agg``
(inside SUM / AVG and similar) or ``raw`` (values returned to the caller,
including a projected MIN / MAX, which returns one row's value). The monitor parses every query
before it runs and reports, per query (stateless) and per session (stateful):

* drift   -- sensitivity-weighted use of columns beyond what the purpose
             allows; the session score counts each (column, mode) once, so a
             long session that repeats the same slip does not grow.
* cell    -- 1 / size of the smallest group an aggregate over a protected
             column is computed on (small cells reveal individuals). The
             session score also catches differencing ("tracker") attacks: two
             aggregates whose entity sets are nested and differ by d entities
             score 1 / d.
* breadth -- distinct entities whose sensitive columns were returned raw,
             divided by the purpose's entity budget.

``cell`` and ``breadth`` need the entity keys a query would touch. The monitor
gets them by running a rewritten key-only query through ``executor`` (a
read-only connection), before the original query runs. Without an executor
those two signals stay 0.

With ``linear_audit`` the monitor also treats every answered aggregate over a
protected column as a linear equation over per-entity values (SUM directly;
AVG together with the COUNT any caller can obtain) and refuses a query that
would make some entity's value exactly derivable from the answered set, by
any combination of queries (the classic audit-expert test of Chin and
Ozsoyoglu). Pairwise differencing remains the k-anonymity-style check for
"fewer than k" rather than "exactly one".

Limits of the prototype: CTEs, set operations and correlated subqueries are
not rewritten; HAVING is dropped from key-set rewrites (groups it would hide
still count); an entity joined to several rows enters an answer with that
multiplicity, so answers are weighted sums and the audits use the weights
(Gram-Schmidt on weight vectors, containment of multisets); refusal decisions
depend on which entities match a query, so a refusal can itself leak
membership (audits are not simulatable).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

import numpy as np
import sqlglot
from pydantic import BaseModel, Field
from sqlglot import exp
from sqlglot.optimizer.qualify import qualify

LEVEL = {"none": 0, "filter": 1, "agg": 2, "raw": 3}

Executor = Callable[[str], list[tuple]]


class PurposeSpec(BaseModel):
    columns: dict[str, str]                                   # "table.column" -> filter | agg | raw
    entity_budget: dict[str, int] = Field(default_factory=dict)  # entity table -> max entities seen raw


class PurposePolicy(BaseModel):
    dialect: str = "sqlite"
    schema_: dict[str, dict[str, str]] = Field(alias="schema")   # table -> column -> type
    entities: dict[str, str] = Field(default_factory=dict)       # entity table -> key column
    sensitivity: dict[str, float] = Field(default_factory=dict)  # "table.column" -> weight
    default_sensitivity: float = 0.1
    protected_threshold: float = 0.5   # sensitivity at which a column gets cell / breadth checks
    default_entity_budget: int = 25
    max_tracked_sets: int = 5000       # aggregate entity sets kept per protected column for pairwise checks
    min_isolation: int | None = None   # audit mode: refuse a query whose aggregate isolates fewer entities
    linear_audit: bool = False         # also refuse a query that makes one entity's value exactly derivable
    max_linear_sets: int = 2000        # groups per query the linear audit will handle; more are refused
    enforce_entity_budget: bool = False  # refuse a query that would exceed the purpose's entity budget
    fail_closed: bool = True           # refuse guarded queries whose entity sets cannot be computed
    strict_protected: bool = False     # refuse predicates on protected columns: audit decisions then
                                       # depend only on non-protected data (simulatable)
    exact_linear: bool = False         # rank test over the rationals (integer weights); the default
                                       # remains the float Gram-Schmidt test with TOL = 1e-9
    audit_predicates: bool = True      # audit predicates on protected columns (e.g. COUNT ... WHERE
                                       # key = 570 AND balance > x): candidate sets, with the protected
                                       # predicates relaxed, get the cell / pairwise / linear tests
    purposes: dict[str, PurposeSpec]

    def weight(self, col: str) -> float:
        return self.sensitivity.get(col, self.default_sensitivity)


@dataclass
class QueryUses:
    uses: dict[str, str]          # "table.column" -> highest mode it is used in
    aliases: dict[str, str]       # alias -> table
    tree: exp.Expression | None   # qualified tree, None if unparseable
    predicates: set = field(default_factory=set)   # columns used outside aggregates and the select list
    opaque: bool = False          # CTE, derived table or set operation: entity sets cannot be audited


@dataclass
class PurposeSignals:
    drift_q: float = 0.0
    cell_q: float = 0.0
    breadth_q: float = 0.0
    drift: float = 0.0
    cell: float = 0.0
    breadth: float = 0.0
    refuse: bool = False          # audit mode: answering would isolate < min_isolation entities
    violations: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)


def _mode(col: exp.Column, projected: bool) -> str:
    """COUNT reveals cardinality only (filter); MIN / MAX return an actual value (raw when projected)."""
    agg = col.find_ancestor(exp.AggFunc)
    if agg is None:
        return "raw" if projected else "filter"
    if isinstance(agg, exp.Count):
        return "filter"
    if projected and isinstance(agg, (exp.Min, exp.Max)):
        return "raw"
    return "agg"


def analyze(sql: str, policy: PurposePolicy) -> QueryUses:
    """Resolve every column to table.column and the mode it is used in."""
    try:
        tree = qualify(sqlglot.parse_one(sql, read=policy.dialect), schema=policy.schema_,
                       dialect=policy.dialect, validate_qualify_columns=False)
    except sqlglot.errors.SqlglotError:
        return QueryUses({}, {}, None)
    aliases = {t.alias_or_name: t.name.lower() for t in tree.find_all(exp.Table)}
    top = [tree] if isinstance(tree, exp.Select) else [s for s in tree.find_all(exp.Select)
                                                       if s.parent_select is None]
    projected: set[int] = set()
    uses: dict[str, str] = {}
    predicates: set[str] = set()

    def note(col: exp.Column, mode: str) -> None:
        table = aliases.get(col.table)
        if not table:
            return                                     # output alias or CTE column
        key = f"{table}.{col.name.lower()}"
        if mode == "filter" and col.find_ancestor(exp.AggFunc) is None:
            predicates.add(key)
        if LEVEL[mode] > LEVEL.get(uses.get(key, "none"), 0):
            uses[key] = mode

    for sel in top:
        for e in sel.expressions:
            for c in e.find_all(exp.Column):
                projected.add(id(c))
                note(c, _mode(c, projected=True))
    for c in tree.find_all(exp.Column):
        if id(c) not in projected:
            note(c, _mode(c, projected=False))
    opaque = (any(True for _ in tree.find_all(exp.CTE, exp.Union, exp.Intersect, exp.Except))
              or any(isinstance(sq.parent, (exp.From, exp.Join)) for sq in tree.find_all(exp.Subquery)))
    return QueryUses(uses, aliases, tree, predicates, opaque)


def violations(q: QueryUses, spec: PurposeSpec, policy: PurposePolicy) -> dict[str, float]:
    """(column:mode) -> sensitivity weight, for uses beyond the purpose's allowance."""
    out = {}
    for col, mode in q.uses.items():
        if LEVEL[mode] > LEVEL[spec.columns.get(col, "none")]:
            out[f"{col}:{mode}"] = policy.weight(col)
    return out


def _key_weights(tree: exp.Expression, alias: str, key: str, executor: Executor, dialect: str,
                 grouped: bool) -> list[dict] | None:
    """Per output group (or the whole result): entity key -> number of rows it contributes.

    A SUM over ``customer JOIN orders`` counts each customer once per order, so the answer is a
    weighted sum of per-entity values; the weights are these row counts. Returns None when they
    cannot be computed (unsupported shape or a failed rewrite), and [] when nothing matches.
    """
    if not isinstance(tree, exp.Select):
        return None
    q = tree.copy()
    group = q.args.get("group")
    group_exprs = [g.copy() for g in group.expressions] if (grouped and group) else []
    q.set("expressions", [exp.column(key, table=alias)] + group_exprs)
    for arg in ("group", "having", "order", "distinct"):
        q.set(arg, None)
    if grouped:
        q.set("limit", None)        # LIMIT applies to groups, not to contributing rows
    try:
        rows = executor(q.sql(dialect=dialect))
    except Exception:
        return None
    groups: dict[tuple, dict] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        if r[0] is not None:
            groups[tuple(r[1:])][r[0]] += 1
    return [dict(g) for g in groups.values() if g]


def _key_sets(tree: exp.Expression, alias: str, key: str, executor: Executor, dialect: str,
              grouped: bool) -> list[frozenset] | None:
    """Entity keys each output group (or the whole result) is computed from (supports of the weights)."""
    w = _key_weights(tree, alias, key, executor, dialect, grouped)
    return None if w is None else [frozenset(g) for g in w]


def _weights(x) -> dict:
    """A weight vector as a dict; a plain set of keys has unit weights."""
    return dict(x) if isinstance(x, dict) else dict.fromkeys(x, 1)


def _isolation(new: list, prior: list) -> int:
    """Smallest number of entities one answer, or the difference of two nested answers, rests on.

    Answers are weight vectors. ``u`` is nested in ``v`` when u <= v entrywise; then v - u is the
    answer over the entities where they differ, with those multiplicities.
    """
    isolated = min(len(x) for x in new)
    for a in new:
        for b in prior:
            small, big = (a, b) if len(a) <= len(b) else (b, a)
            if all(big.get(k, 0) >= w for k, w in small.items()):
                d = sum(1 for k, w in big.items() if w > small.get(k, 0))
                if d:
                    isolated = min(isolated, d)
    return isolated


def _bare_argument(agg: exp.Expression, cols: set[str], aliases: dict[str, str]) -> bool:
    """True if the aggregate's argument is a protected column on its own (casts and parentheses aside)."""
    if agg.args.get("distinct") or isinstance(agg.this, exp.Distinct):
        return False                        # SUM(DISTINCT x) collapses equal values: not linear
    node = agg.this
    while isinstance(node, (exp.Cast, exp.Paren)):
        node = node.this
    return isinstance(node, exp.Column) and f"{aliases.get(node.table)}.{node.name.lower()}" in cols

_ATOMS = (exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE, exp.Between, exp.In, exp.Like, exp.ILike,
          exp.Is, exp.NullSafeEQ, exp.NullSafeNEQ)


def _relax(tree: exp.Expression, cols: set[str], aliases: dict[str, str]) -> exp.Expression | None:
    """Copy of ``tree`` with every predicate on a protected column in ``cols`` replaced by TRUE.

    The relaxed query matches a superset of the original's rows: the candidate entities whose
    protected values the original answer depends on. Only comparison atoms joined by AND / OR in
    the top-level WHERE are supported; any other use outside an aggregate (NOT, CASE, JOIN ON,
    GROUP BY, ORDER BY, HAVING, a subquery) returns None, which the caller refuses.
    """
    if not isinstance(tree, exp.Select):
        return None
    q = tree.copy()
    where = q.args.get("where")
    atoms: dict[int, exp.Expression] = {}
    for col in list(q.find_all(exp.Column)):
        if f"{aliases.get(col.table)}.{col.name.lower()}" not in cols or col.find_ancestor(exp.AggFunc):
            continue
        if col.parent_select is not q or where is None:
            return None
        atom, node = None, col.parent
        while node is not None and node is not where:
            if isinstance(node, _ATOMS) and atom is None:
                atom = node
            elif atom is not None and not isinstance(node, (exp.And, exp.Or, exp.Paren)):
                return None                            # NOT, CASE, ... : relaxing is not a superset
            elif atom is None and not isinstance(node, (exp.Column, exp.Cast, exp.Paren, exp.Neg,
                                                         exp.Binary, exp.Literal, exp.Tuple)):
                return None
            node = node.parent
        if node is None or atom is None:
            return None                                # not in WHERE (JOIN ON, GROUP BY, ORDER BY ...)
        atoms[id(atom)] = atom
    for atom in atoms.values():
        atom.replace(exp.true())
    return q


class LinearAuditor:
    """Orthonormal basis of the answered queries' weight vectors (0/1 indicators for plain sets).

    Entity i's value is exactly derivable iff the unit vector e_i lies in the
    span, i.e. the i-th diagonal entry of the projection Q Q^T equals 1.
    """

    TOL = 1e-9

    def __init__(self):
        self.index: dict = {}
        self.Q = np.zeros((0, 0))

    def _grow(self, keys) -> None:
        new = [k for k in keys if k not in self.index]
        for k in new:
            self.index[k] = len(self.index)
        if new:
            self.Q = np.vstack([self.Q, np.zeros((len(new), self.Q.shape[1]))])

    def _add(self, Q: np.ndarray, keys) -> np.ndarray:
        v = np.zeros(Q.shape[0])
        for k, w in _weights(keys).items():
            v[self.index[k]] = float(w)
        v /= np.linalg.norm(v) or 1.0
        for _ in range(2):                       # re-orthogonalise for stability
            v = v - Q @ (Q.T @ v)
        n = np.linalg.norm(v)
        return np.hstack([Q, (v / n)[:, None]]) if n > 1e-7 else Q

    def disclosed(self, sets: list[frozenset]) -> list:
        """Entities whose value would become exactly derivable if ``sets`` were answered."""
        self._grow(set().union(*sets))
        Q = self.Q
        for s in sets:
            Q = self._add(Q, s)
        diag = (Q ** 2).sum(axis=1)
        keys = list(self.index)
        return [keys[i] for i in np.nonzero(diag > 1 - self.TOL)[0]]

    def commit(self, sets: list[frozenset]) -> None:
        self._grow(set().union(*sets))
        for s in sets:
            self.Q = self._add(self.Q, s)


class ExactLinearAuditor:
    """Same test as ``LinearAuditor``, over the rationals, for integer weights.

    Row counts are integers, so the span membership test does not need a
    floating-point tolerance. Entity ``i`` is exactly derivable when the
    reduced basis contains the unit vector ``e_i``. ``disclosed`` returns every
    such entity after the new sets are added, including ones already derivable,
    matching ``LinearAuditor``.
    """

    def __init__(self):
        from fractions import Fraction
        self._F = Fraction
        self.index: dict = {}
        self.rows: list[tuple] = []          # (pivot key, {key: Fraction}) in RREF

    def _touch(self, keys) -> None:
        for k in keys:
            if k not in self.index:
                self.index[k] = len(self.index)

    def _vec(self, keys) -> dict:
        F = self._F
        return {k: F(int(w)) for k, w in _weights(keys).items() if int(w) != 0}

    def _insert(self, rows: list, vec: dict) -> list:
        v = dict(vec)
        for pivot, row in rows:
            coef = v.get(pivot)
            if not coef:
                continue
            for k, w in row.items():
                nv = v.get(k, 0) - coef * w
                if nv:
                    v[k] = nv
                else:
                    v.pop(k, None)
        if not v:
            return rows
        pivot = min(v, key=lambda k: self.index[k])
        scale = v[pivot]
        v = {k: w / scale for k, w in v.items()}
        out = []
        for p, row in rows:
            coef = row.get(pivot)
            if coef:
                row = dict(row)
                for k, w in v.items():
                    nv = row.get(k, 0) - coef * w
                    if nv:
                        row[k] = nv
                    else:
                        row.pop(k, None)
            out.append((p, row))
        out.append((pivot, v))
        out.sort(key=lambda pr: self.index[pr[0]])
        return out

    @staticmethod
    def _units(rows) -> list:
        return [p for p, row in rows if len(row) == 1 and row.get(p) == 1]

    def _advance(self, sets, commit: bool):
        vecs = [self._vec(s) for s in sets]
        vecs = [v for v in vecs if v]
        self._touch(set().union(*vecs) if vecs else set())
        rows = self.rows
        for v in vecs:
            rows = self._insert(rows, v)
        found = self._units(rows)
        if commit:
            self.rows = rows
        return found

    def disclosed(self, sets: list) -> list:
        return self._advance(sets, commit=False)

    def commit(self, sets: list) -> None:
        self._advance(sets, commit=True)


class PurposeMonitor:
    """One session (subject + declared purpose). Call ``check`` before each query runs."""

    def __init__(self, policy: PurposePolicy, purpose: str, executor: Executor | None = None):
        if purpose not in policy.purposes:
            raise KeyError(f"unknown purpose {purpose!r}")
        self.policy, self.spec, self.executor = policy, policy.purposes[purpose], executor
        self.seen_violations: dict[str, float] = {}
        self.agg_sets: dict[str, list[dict]] = defaultdict(list)        # entity.protected col -> weight vectors
        aud = ExactLinearAuditor if policy.exact_linear else LinearAuditor
        self.linear: dict = defaultdict(aud)
        self.revealed: dict[str, set] = defaultdict(set)                 # entity table -> keys
        self.pred_sets: dict[str, list[dict]] = defaultdict(list)       # candidate sets of predicate queries
        self.pred_linear: dict = defaultdict(aud)
        self.cell = 0.0

    def _predicate_audit(self, q: QueryUses, s: PurposeSignals) -> list[tuple[str, list[dict]]]:
        """Audit predicates on protected columns; returns the candidate sets to commit if admitted.

        A filter such as ``key = 570 AND balance > x`` makes the answer depend on one entity's
        protected value even though the column is never aggregated. The candidate sets (one per
        output group of the query with protected predicates relaxed) are the entities the answer
        depends on; a non-aggregate query is treated as one group per entity. They get the same
        small-cell, nested-pair and linear tests as aggregates, against a separate history: answers
        that depend on thresholds of the value are a different unknown than its sums. Treating all
        thresholds as one unknown is a conservative heuristic, not a proof (strict mode is the
        variant with a guarantee).
        """
        p = self.policy
        cols = sorted(c for c in q.predicates if c in self._protected_cols())
        if not cols or not p.min_isolation:
            return []
        protected = self._protected_cols()
        for agg in q.tree.find_all(exp.AggFunc):
            used = {f"{q.aliases.get(c.table)}.{c.name.lower()}" for c in agg.find_all(exp.Column)}
            if not isinstance(agg, exp.Count) and not used <= protected:
                # e.g. SUM(known weight) over the matches: distinct weights decode which entities matched
                s.refuse, s.cell_q = True, 1.0       # treated as isolating one entity
                s.reasons.append(f"refused: {agg.key.upper()} over non-protected values under a predicate on "
                                 + ", ".join(cols) + " (only COUNT or aggregates of the protected column)")
                return []
        relaxed = _relax(q.tree, set(cols), q.aliases)
        if relaxed is None:
            s.refuse, s.cell_q = True, 1.0           # treated as isolating one entity
            s.reasons.append("refused: predicate on protected column " + ", ".join(cols) +
                             " in a shape the audit cannot relax (NOT, CASE, JOIN ON, GROUP BY, ORDER BY, subquery)")
            return []
        by_table = {t: a for a, t in q.aliases.items()}
        aggregate = bool(q.tree.args.get("group")) or any(
            e.find(exp.AggFunc) for e in q.tree.expressions)
        out = []
        for col in cols:
            table = col.split(".")[0]
            alias, key = by_table.get(table), p.entities[table]
            sets = None if alias is None else _key_weights(relaxed, alias, key, self.executor, p.dialect,
                                                            grouped=aggregate)
            if sets is None:
                s.refuse, s.cell_q = True, 1.0
                s.reasons.append(f"refused: candidate entities for the predicate on {col} could not be computed")
                return []
            if not aggregate:
                sets = [{k: 1} for k in set().union(*sets)] if sets else []
            elif not self._distinct_entity_count(q, alias, key):
                # COUNT(*) over a join counts an entity once per row; unequal multiplicities let the
                # count decode which candidates matched (3 orders vs 1 + 1), so require equal weights
                uneven = next((g for g in sets if len(set(g.values())) > 1), None)
                if uneven is not None:
                    s.refuse, s.cell_q = True, 1.0
                    s.reasons.append(f"refused: predicate on {col} over rows that count entities unequally "
                                     f"(use COUNT(DISTINCT {key}))")
                    return []
            sets = [dict.fromkeys(g, 1) for g in sets]
            if not sets:
                continue
            isolated = _isolation(sets, self.pred_sets[col])
            if p.linear_audit and isolated >= p.min_isolation:
                if len(sets) > p.max_linear_sets:
                    isolated = 0
                elif self.pred_linear[col].disclosed(sets):
                    isolated = 1
            s.cell_q = max(s.cell_q, 1.0 / max(isolated, 1))
            if isolated < p.min_isolation:
                s.refuse = True
                s.reasons.append(f"refused: predicate on {col} would depend on {isolated or 'too many groups of'} "
                                 f"entities' values (minimum {p.min_isolation})")
                return []
            out.append((col, sets))
        return out

    @staticmethod
    def _distinct_entity_count(q: QueryUses, alias: str, key: str) -> bool:
        """True if every aggregate is COUNT(DISTINCT <entity key>): each entity then counts once."""
        aggs = list(q.tree.find_all(exp.AggFunc))
        def ok(a):
            d = a.this
            if not (isinstance(a, exp.Count) and isinstance(d, exp.Distinct) and len(d.expressions) == 1):
                return False
            c = d.expressions[0]
            return isinstance(c, exp.Column) and c.table == alias and c.name.lower() == key.lower()
        return bool(aggs) and all(ok(a) for a in aggs)

    def _protected_agg(self, q: QueryUses) -> list[str]:
        p = self.policy
        return [c for c, m in q.uses.items() if m == "agg" and p.weight(c) >= p.protected_threshold
                and c.split(".")[0] in p.entities]

    def _raw_sensitive(self, q: QueryUses) -> list[str]:
        p = self.policy
        return [c for c, m in q.uses.items() if m == "raw" and p.weight(c) >= p.protected_threshold
                and c.split(".")[0] in p.entities]

    def check(self, sql: str) -> PurposeSignals:
        p, s = self.policy, PurposeSignals()
        q = analyze(sql, p)
        v = violations(q, self.spec, p)
        s.violations = v
        s.drift_q = sum(v.values())
        self.seen_violations.update(v)
        if v:
            s.reasons.append("beyond purpose: " + ", ".join(sorted(v)))

        if p.strict_protected:
            bad = sorted(c for c in q.predicates if c in self._protected_cols())
            if bad:
                s.refuse = True
                s.reasons.append("refused: predicate on protected column " + ", ".join(bad))
                return self._finish(s)

        if self.executor is not None and p.fail_closed:
            guarded = self._protected_cols() | self._sensitive_cols()
            touched = sorted(c for c in q.uses if c in guarded)
            tables = [t for t in q.aliases.values()]
            repeated = any(tables.count(c.split(".")[0]) > 1 for c in touched)
            if touched and (q.tree is None or q.opaque or repeated):
                s.refuse, s.cell_q = True, 1.0       # unauditable: treated as isolating one entity
                s.reasons.append("refused: query shape cannot be audited (CTE, derived table, set operation "
                                 "or repeated entity table) for " + ", ".join(touched))
                return self._finish(s)

        pending: list[tuple[str, list[dict]]] = []
        if self.executor is not None and q.tree is not None and p.audit_predicates:
            pending = self._predicate_audit(q, s)
            if s.refuse:
                return self._finish(s)

        if self.executor is not None and q.tree is not None:
            by_table = {t: a for a, t in q.aliases.items()}
            for col in self._protected_agg(q):
                table = col.split(".")[0]
                bad = [a for a in q.tree.find_all(exp.AggFunc) if not isinstance(a, exp.Count)
                       and any(f"{q.aliases.get(c.table)}.{c.name.lower()}" == col for c in a.find_all(exp.Column))
                       and not _bare_argument(a, {col}, q.aliases)]
                if bad:
                    # SUM(x * w), SUM(CASE ...), SUM(DISTINCT x): the answer is not the audited weighted sum
                    s.refuse, s.cell_q = True, 1.0
                    s.reasons.append(f"refused: {bad[0].key.upper()} over an expression of {col}; "
                                     "only the bare column can be audited")
                    return self._finish(s)
                alias, key = by_table.get(table), p.entities[table]
                sets = None if alias is None else _key_weights(q.tree, alias, key, self.executor, p.dialect,
                                                                grouped=True)
                if sets is None:
                    if p.fail_closed:
                        s.refuse, s.cell_q = True, 1.0
                        s.reasons.append(f"refused: entity sets for {col} could not be computed")
                        return self._finish(s)
                    continue
                if not sets:
                    continue                     # matches no entity: reveals nothing
                s.cell_q = max(s.cell_q, 1.0 / min(len(x) for x in sets))
                prior = self.agg_sets[col]
                isolated = _isolation(sets, prior)
                exact = []
                if p.linear_audit and not (p.min_isolation and isolated < p.min_isolation):
                    if len(sets) > p.max_linear_sets:     # too many groups to audit exactly: refuse
                        isolated = 0
                        s.reasons.append(f"{len(sets)} groups exceed the linear audit limit")
                    else:
                        exact = self.linear[col].disclosed(sets)
                if exact:
                    isolated = 1
                if p.min_isolation and isolated < p.min_isolation:
                    s.refuse = True
                    why = (f"would make {len(exact)} entities' {col} exactly derivable" if exact
                           else "exceeds the audit limit" if isolated == 0
                           else f"would isolate {isolated} entities")
                    s.reasons.append(f"refused: aggregate over {col} {why} (minimum {p.min_isolation})")
                    continue                     # a refused query reveals nothing; keep state unchanged
                if p.linear_audit:
                    self.linear[col].commit(sets)
                prior.extend(sets)
                del prior[:-p.max_tracked_sets]
                if 1.0 / isolated > self.cell:
                    self.cell = 1.0 / isolated
                    s.reasons.append(f"aggregate over {col} isolates {isolated} entities")

            for col in self._raw_sensitive(q):
                table = col.split(".")[0]
                alias = by_table.get(table)
                found = None if alias is None else _key_sets(q.tree, alias, p.entities[table], self.executor,
                                                              p.dialect, grouped=False)
                if found is None:
                    if p.fail_closed:
                        s.refuse = True
                        s.reasons.append(f"refused: entities returned for {col} could not be computed")
                        return self._finish(s)
                    continue
                keys = set().union(*found) if found else set()
                budget = self.spec.entity_budget.get(table, p.default_entity_budget)
                s.breadth_q = max(s.breadth_q, len(keys) / budget)
                seen = self.revealed[table] | keys
                if p.enforce_entity_budget and len(seen) > budget:
                    s.refuse = True
                    s.reasons.append(f"refused: {table} sensitive columns would be returned for "
                                     f"{len(seen)} entities (budget {budget})")
                    continue                     # refused: nothing returned, keep state
                self.revealed[table] = seen
                if len(seen) > budget:
                    s.reasons.append(f"{table}: sensitive columns returned for {len(seen)} entities (budget {budget})")

        if not s.refuse:                         # a refused query reveals nothing
            for col, sets in pending:
                if p.linear_audit:
                    self.pred_linear[col].commit(sets)
                self.pred_sets[col].extend(sets)
                del self.pred_sets[col][:-p.max_tracked_sets]
        return self._finish(s)

    def _protected_cols(self) -> set[str]:
        p = self.policy
        return {c for c, m in self.spec.columns.items() if m == "agg" and p.weight(c) >= p.protected_threshold
                and c.split(".")[0] in p.entities}

    def _sensitive_cols(self) -> set[str]:
        """Sensitive entity columns: their raw values count toward the entity budget."""
        p = self.policy
        return {c for t in p.entities for c in (f"{t}.{col.lower()}" for col in p.schema_.get(t, {}))
                if p.weight(c) >= p.protected_threshold}

    def _finish(self, s: PurposeSignals) -> PurposeSignals:
        p = self.policy
        s.drift = sum(self.seen_violations.values())
        s.cell = self.cell
        s.breadth = max((len(k) / self.spec.entity_budget.get(t, p.default_entity_budget)
                         for t, k in self.revealed.items()), default=0.0)
        return s
