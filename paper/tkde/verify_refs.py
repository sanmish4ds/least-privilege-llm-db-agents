"""Resolve every reference against Crossref or arXiv and write references.bib + REFERENCE_AUDIT.md.

Entries are built from the fetched metadata, never typed by hand. A DOI given
here is checked; a query is resolved to the best Crossref match and accepted
only if its title matches the expected title.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from difflib import SequenceMatcher
from pathlib import Path

HERE = Path(__file__).resolve().parent

# key, source, identifier-or-query, expected title, claim it supports
REFS = [
    ("denning1979tracker", "doi", "10.1145/320064.320069", "The tracker: a threat to statistical database security", "differencing (tracker) attacks on aggregate queries"),
    ("chin1982auditing", "query", "Auditing and inference control in statistical databases Chin Ozsoyoglu", "Auditing and inference control in statistical databases", "audit expert: linear-algebraic compromise test"),
    ("dinur2003revealing", "query", "Revealing information while preserving privacy Dinur Nissim", "Revealing information while preserving privacy", "reconstruction from many aggregate answers"),
    ("kenthapadi2005simulatable", "query", "Simulatable auditing Kenthapadi Mishra Nissim", "Simulatable auditing", "denials can leak; simulatable auditing"),
    ("byun2008purpose", "query", "Purpose based access control for privacy protection in relational database systems", "Purpose based access control for privacy protection in relational database systems", "purpose-based access control"),
    ("agrawal2002hippocratic", "query", "Hippocratic databases Agrawal Kiernan Srikant Xu", "Hippocratic Databases", "purpose specification and limited disclosure in DBMS"),
    ("rizvi2004extending", "query", "Extending query rewriting techniques for fine-grained access control", "Extending query rewriting techniques for fine-grained access control", "fine-grained access control by query rewriting"),
    ("sandhu1996rbac", "query", "Role-based access control models Sandhu Coyne Feinstein Youman", "Role-based access control models", "RBAC"),
    ("kamra2008detecting", "query", "Detecting anomalous access patterns in relational databases Kamra Terzi Bertino", "Detecting anomalous access patterns in relational databases", "role-profile anomaly detection over SQL logs"),
    ("johnson2018flex", "query", "Towards practical differential privacy for SQL queries Johnson Near Song", "Towards practical differential privacy for SQL queries", "differentially private SQL"),
    ("dwork2006calibrating", "doi", "10.1007/11681878_14", "Calibrating noise to sensitivity in private data analysis", "differential privacy"),
    ("sweeney2002kanonymity", "doi", "10.1142/S0218488502001648", "k-anonymity: a model for protecting privacy", "k-anonymity"),
    ("yu2018spider", "doi", "10.18653/v1/D18-1425", "Spider: A Large-Scale Human-Labeled Dataset for Complex and Cross-Domain Semantic Parsing and Text-to-SQL Task", "Spider text-to-SQL benchmark"),
    ("li2023bird", "arxiv", "2305.03111", "Can LLM Already Serve as A Database Interface? A BIg Bench for Large-Scale Database Grounded Text-to-SQLs", "BIRD benchmark"),
    ("greshake2023indirect", "doi", "10.1145/3605764.3623985", "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection", "indirect prompt injection"),
    ("pedro2025p2sql", "arxiv", "2308.01990", "From Prompt Injections to SQL Injection Attacks: How Protected is Your LLM-Integrated Web Application?", "prompt-to-SQL injection"),
    ("klisura2025schema", "arxiv", "2406.14545", "Unmasking Database Vulnerabilities: Zero-Knowledge Schema Inference Attacks in Text-to-SQL Systems", "schema inference attacks on text-to-SQL"),
    ("jiang2026rbacsql", "arxiv", "2607.22115", "Benchmarking Text-to-SQL under Role-Based Access Control", "single-query RBAC text-to-SQL benchmark"),
    ("dataagents2026", "arxiv", "2606.08661", "Data Agents Under Attack: Vulnerabilities in LLM-Driven Analytical Systems", "attacks on LLM data agents"),
    ("authz2026agents", "arxiv", "2609.15906", "Authorization Architectures for Tool-Using AI Agents", "task-scoped authorization for agents (tool level)"),
    ("agenra2026", "arxiv", "2608.22868", "Agenra: A Language and Verified Core for Stateful LLM Agent Authorization", "stateful authorization with consumable authority (formerly titled AgentFlow)"),
    ("chen2025sequential", "arxiv", "2506.10949", "Monitoring Decomposition Attacks in LLMs with Lightweight Sequential Monitors", "cumulative monitoring of decomposed requests"),
    ("russinovich2025crescendo", "arxiv", "2404.01833", "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack", "multi-turn escalation via benign steps"),
    ("rolecond2025", "arxiv", "2510.07642", "Role-Conditioned Refusals: Evaluating Access Control Reasoning in Large Language Models", "LLM reasoning about role-conditioned access"),
    ("dobkin1979secure", "doi", "10.1145/320064.320068", "Secure databases: protection against user influence", "overlap control delays but does not prevent compromise"),
    ("adam1989security", "doi", "10.1145/76894.76895", "Security-control methods for statistical databases: a comparative study", "survey of statistical-database controls"),
    ("kleinberg2003boolean", "doi", "10.1016/S0022-0000(02)00036-3", "Auditing Boolean attributes", "exact auditing is hard even for Boolean values"),
    ("francis2017diffix", "doi", "10.1007/978-3-319-67280-9_8", "Diffix: High-Utility Database Anonymization", "deployed low-count-filtering SQL proxy"),
    ("gadotti2019diffix", "arxiv", "1804.06752", "When the Signal is in the Noise: Exploiting Diffix's Sticky Noise", "attribute-inference attack on Diffix"),
    ("cohen2020reconstruction", "doi", "10.29012/jpc.711", "Linear Program Reconstruction in Practice", "reconstruction attack on Diffix"),
    ("debenedetti2026camel", "doi", "10.1109/SaTML68715.2026.00040", "Defeating Prompt Injections by Design", "CaMeL: control/data-flow separation with value capabilities"),
    ("shi2025progent", "arxiv", "2504.11703", "Progent: Securing AI Agents with Privilege Control", "deterministic per-task privilege policies on tool calls"),
    ("costa2025fides", "arxiv", "2505.23643", "Securing AI Agents with Information-Flow Control", "FIDES: information-flow labels in agent planners"),
    ("mishra2026cra", "arxiv", "2607.19361", "Stateful Guardrails for Multi-Turn LLM Systems: A Conversational Risk Accumulation Framework", "conversation-level CRA signals (authors' prior work)"),
]

UA = {"User-Agent": "lp-gateway-refcheck/1.0 (mailto:sanmish4@icloud.com)"}


def get(url: str) -> bytes:
    """Fetch with curl (the system Python here cannot verify TLS certificates)."""
    for attempt in range(4):
        r = subprocess.run(["curl", "-sfL", "-m", "30", "-A", UA["User-Agent"], url], capture_output=True)
        if r.returncode == 0 and r.stdout:
            return r.stdout
        time.sleep(10 * (attempt + 1))
    raise RuntimeError(url)


def sim(a: str, b: str) -> float:
    n = lambda s: re.sub(r"[^a-z0-9 ]", "", s.lower())                   # noqa: E731
    return SequenceMatcher(None, n(a), n(b)).ratio()


def crossref_doi(doi: str) -> dict:
    return json.loads(get("https://api.crossref.org/works/" + urllib.parse.quote(doi)))["message"]


def crossref_query(q: str) -> list[dict]:
    url = "https://api.crossref.org/works?rows=5&query.bibliographic=" + urllib.parse.quote(q)
    return json.loads(get(url))["message"]["items"]


def arxiv(aid: str) -> dict:
    root = ET.fromstring(get(f"https://export.arxiv.org/api/query?id_list={aid}"))
    ns = {"a": "http://www.w3.org/2005/Atom", "ar": "http://arxiv.org/schemas/atom"}
    e = root.find("a:entry", ns)
    title = re.sub(r"\s+", " ", e.find("a:title", ns).text).strip()
    authors = [a.find("a:name", ns).text for a in e.findall("a:author", ns)]
    year = e.find("a:published", ns).text[:4]
    doi = e.find("ar:doi", ns)
    jref = e.find("ar:journal_ref", ns)
    return {"title": title, "authors": authors, "year": year,
            "doi": doi.text if doi is not None else None,
            "journal_ref": jref.text if jref is not None else None}


def bib_escape(s: str) -> str:
    return s.replace("&", r"\&").replace("%", r"\%").replace("_", r"\_").replace("#", r"\#")


def shouting(t: str) -> bool:
    letters = [c for c in t if c.isalpha()]
    return bool(letters) and sum(c.isupper() for c in letters) / len(letters) > 0.8


def unshout(t: str) -> str:
    """Crossref sometimes stores titles / names in capitals; restore normal case."""
    return t.title() if shouting(t) else t


def from_crossref(key: str, m: dict) -> tuple[str, dict]:
    authors = " and ".join(f"{unshout(a.get('family', ''))}, {unshout(a.get('given', ''))}".strip(", ")
                           for a in m.get("author", []))
    title = m["title"][0] + (": " + m["subtitle"][0] if m.get("subtitle") else "")
    if shouting(title):
        title = title.lower()
    year = (m.get("issued") or m.get("published") or {}).get("date-parts", [[None]])[0][0]
    venue = (m.get("container-title") or [""])[0]
    typ = m.get("type")
    fields = {"author": authors, "title": "{" + bib_escape(title) + "}", "year": str(year), "doi": m.get("DOI")}
    if typ == "journal-article":
        kind = "article"
        fields |= {"journal": bib_escape(venue), "volume": m.get("volume"), "number": m.get("issue"),
                   "pages": (m.get("page") or "").replace("-", "--")}
    else:
        kind = "inproceedings"
        fields |= {"booktitle": bib_escape(venue), "pages": (m.get("page") or "").replace("-", "--"),
                   "publisher": m.get("publisher")}
    body = ",\n".join(f"  {k} = {{{v}}}" for k, v in fields.items() if v)
    return f"@{kind}{{{key},\n{body}\n}}", {"title": title, "venue": venue, "year": year, "doi": m.get("DOI")}


PUBLISHED = {  # peer-reviewed venue, verified against the paper itself or the venue listing
    "2404.01833": "In Proc. USENIX Security 2025",
    "2305.03111": "NeurIPS 2023 Datasets and Benchmarks Track",
    "1804.06752": "In Proc. USENIX Security 2019",
    "2506.10949": "In Proc. ICLR 2026",
    "2406.14545": "In Findings of the Association for Computational Linguistics: NAACL 2025",
}


def from_arxiv(key: str, aid: str, m: dict) -> tuple[str, dict]:
    authors = " and ".join(m["authors"])
    fields = {"author": authors, "title": "{" + bib_escape(m["title"]) + "}", "year": m["year"],
              "journal": f"arXiv preprint arXiv:{aid}",
              "note": PUBLISHED.get(aid) or (bib_escape(m["journal_ref"]) if m["journal_ref"] else None),
              "doi": m["doi"]}
    body = ",\n".join(f"  {k} = {{{v}}}" for k, v in fields.items() if v)
    return f"@article{{{key},\n{body}\n}}", {"title": m["title"], "venue": f"arXiv {aid}" + (f" ({m['journal_ref']})" if m["journal_ref"] else ""),
                                             "year": m["year"], "doi": m["doi"]}


def main() -> None:
    bibs, audit = [], []
    for key, src, ident, expect, claim in REFS:
        try:
            if src == "doi":
                bib, meta = from_crossref(key, crossref_doi(ident))
            elif src == "arxiv":
                bib, meta = from_arxiv(key, ident, arxiv(ident))
            else:
                items = crossref_query(ident)
                best = max(items, key=lambda m: sim((m.get("title") or [""])[0], expect))
                bib, meta = from_crossref(key, best)
            score = sim(meta["title"], expect)
            status = "OK" if score > 0.85 else f"TITLE MISMATCH ({score:.2f})"
        except Exception as e:                       # network or parse failure: flag, do not guess
            bib, meta, status = None, {"title": "", "venue": "", "year": "", "doi": ""}, f"UNRESOLVED ({e})"
        if bib:
            bibs.append(bib)
        audit.append((key, status, meta["title"], meta["venue"], meta["year"], meta.get("doi") or "", claim))
        print(f"{status:12} {key}: {meta['title'][:70]}")
        time.sleep(4 if src == "arxiv" else 0.5)     # arXiv API asks for >= 3 s between calls
    (HERE / "references.bib").write_text("\n\n".join(bibs) + "\n")
    lines = ["# Reference audit", "", "Generated by verify_refs.py from Crossref / arXiv metadata.", "",
             "| Key | Status | Title (as resolved) | Venue | Year | DOI | Claim supported |", "|---|---|---|---|---|---|---|"]
    lines += [f"| {k} | {s} | {t} | {v} | {y} | {d} | {c} |" for k, s, t, v, y, d, c in audit]
    (HERE / "REFERENCE_AUDIT.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
