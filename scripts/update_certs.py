#!/usr/bin/env python3
"""Rebuild Certification Details from tracker issues; Credly fills gaps only."""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

MONTHS = {
    "january": 1,
    "february": 2,
    "march": 3,
    "april": 4,
    "may": 5,
    "june": 6,
    "july": 7,
    "august": 8,
    "september": 9,
    "october": 10,
    "november": 11,
    "december": 12,
}


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def tokens(s: str) -> set[str]:
    stop = {"certification", "certified", "ce", "the", "in", "and", "of", "a"}
    return {t for t in norm(s).split() if len(t) > 1 and t not in stop}


def score_match(issue_title: str, badge_name: str) -> int:
    ti, tb = tokens(issue_title), tokens(badge_name)
    if not ti or not tb:
        return 0
    return len(ti & tb)


def parse_date(raw: str | None) -> str | None:
    """Return YYYY-MM-DD, YYYY-MM, or cleaned original — never invent."""
    if not raw:
        return None
    s = raw.strip().strip("*").strip()
    if not s or s.lower() in {"tbd", "n/a", "na", "none", "-"}:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        return s
    if re.fullmatch(r"\d{4}-\d{2}", s):
        return s
    m = re.fullmatch(
        r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{1,2}),\s*(\d{4})",
        s,
        re.I,
    )
    if m:
        return f"{int(m.group(3)):04d}-{MONTHS[m.group(1).lower()]:02d}-{int(m.group(2)):02d}"
    m = re.fullmatch(
        r"(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})",
        s,
        re.I,
    )
    if m:
        return f"{int(m.group(2)):04d}-{MONTHS[m.group(1).lower()]:02d}"
    # Keep recognizable year-only rather than inventing month/day
    if re.fullmatch(r"\d{4}", s):
        return s
    return s


def issued_sort_key(issued: str) -> tuple[int, int, int]:
    """Newest-first sort key. Undated / N/A sorts last when reverse=True."""
    if not issued or issued.strip().upper() in {"N/A", "", "-"}:
        return (0, 0, 0)
    parts = issued.strip().split("-")
    try:
        y = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else 0
        m = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        d = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0
    except ValueError:
        return (0, 0, 0)
    return (y, m, d)


def field(body: str, *names: str) -> str | None:
    for name in names:
        m = re.search(
            rf"\*\*{re.escape(name)}\*\*\s*:\s*(.+?)(?:\n|$)",
            body,
            re.I,
        )
        if m:
            val = m.group(1).strip()
            if val and not val.lower().startswith("(replace"):
                return val
        m = re.search(rf"^{re.escape(name)}\s*:\s*(.+?)\s*$", body, re.I | re.M)
        if m:
            val = m.group(1).strip()
            if val and not val.lower().startswith("(replace"):
                return val
    return None


def credly_id_from_body(body: str) -> str | None:
    m = re.search(r"\*\*Credly Badge ID\*\*\s*:\s*([a-f0-9-]{36})", body, re.I)
    if m:
        return m.group(1).lower()
    m = re.search(r"credly\.com/badges/([a-f0-9-]{36})", body, re.I)
    if m:
        return m.group(1).lower()
    return None


def issuer_from_badge(badge: dict) -> str | None:
    template = badge.get("badge_template") or {}
    issuer = template.get("issuer") or {}
    entities = issuer.get("entities") or []
    if entities:
        name = ((entities[0] or {}).get("entity") or {}).get("name")
        if name:
            return name
    return None


def issuer_from_labels(labels: list[str]) -> str | None:
    for lab in labels or []:
        m = re.match(r"vendor:(.+)$", lab, re.I)
        if m:
            v = m.group(1).strip()
            if v.upper() == "ISC2":
                return "ISC2"
            return v
    return None


def is_cert_issue(issue: dict) -> bool:
    body = issue.get("body") or ""
    title = issue.get("title") or ""
    labels = issue.get("labels") or []
    if credly_id_from_body(body) or field(body, "Date Certified", "Earned Date"):
        return True
    if any(re.match(r"vendor:", l, re.I) for l in labels):
        return True
    if re.search(r"\b(CompTIA|ISC.?2|CISSP|Security\+|CySA|CCNA|OSCP)\b", title, re.I):
        return True
    return False


def status_for(title: str, expiration: str | None) -> str:
    if re.search(r"\(Expired\)", title, re.I) or re.search(r"\bExpired\b", title, re.I):
        return "Expired"
    if expiration and re.fullmatch(r"\d{4}-\d{2}-\d{2}", expiration):
        try:
            if date.fromisoformat(expiration) < date.today():
                return "Expired"
        except ValueError:
            pass
    return "Active"


def match_badge(issue: dict, badges: list[dict], used: set[str]) -> dict | None:
    body = issue.get("body") or ""
    title = issue.get("title") or ""
    by_id = {b.get("id"): b for b in badges if b.get("id")}
    cid = credly_id_from_body(body)
    if cid and cid in by_id and cid not in used:
        return by_id[cid]

    best, best_score = None, 0
    for b in badges:
        bid = b.get("id")
        if not bid or bid in used:
            continue
        name = (b.get("badge_template") or {}).get("name") or ""
        sc = score_match(title, name)
        if sc > best_score:
            best, best_score = b, sc
    if not best or best_score < 1:
        return None
    bname = (best.get("badge_template") or {}).get("name") or ""
    bname_toks = tokens(bname)
    strong = tokens(title) & {"server", "network", "cybersecurity", "cc"}
    a_plus = bool(re.search(r"\ba\+", title.lower()) and re.search(r"\ba\+", bname.lower()))
    if best_score >= 2 or (strong & bname_toks) or a_plus:
        return best
    return None


def main() -> None:
    badges_path = Path("badges.json")
    issues_path = Path("tracker_issues.json")

    badges: list[dict] = []
    if badges_path.exists():
        raw = json.loads(badges_path.read_text(encoding="utf-8"))
        badges = [
            b
            for b in (raw.get("data") or [])
            if b.get("state") == "accepted" and b.get("badge_template")
        ]

    issues: list[dict] = []
    if issues_path.exists():
        issues = json.loads(issues_path.read_text(encoding="utf-8"))

    cert_issues = [i for i in issues if is_cert_issue(i)]
    # Collect cert rows; final table sorted newest-first by Issued
    cert_issues.sort(key=lambda i: i.get("number") or 0)

    rows: list[dict] = []
    used_badge_ids: set[str] = set()

    for issue in cert_issues:
        number = issue.get("number")
        title = issue.get("title") or ""
        body = issue.get("body") or ""
        labels = issue.get("labels") or []

        badge = match_badge(issue, badges, used_badge_ids)

        # Issue-first fields
        issuer = field(body, "Issuing Body", "Issuer") or issuer_from_labels(labels)
        issued = parse_date(field(body, "Date Certified", "Earned Date"))
        expiration = parse_date(field(body, "Expiration"))

        # Credly fills gaps only
        if badge:
            bid = badge.get("id")
            if bid:
                used_badge_ids.add(bid)
            if not issuer:
                issuer = issuer_from_badge(badge)
            if not issued:
                issued = parse_date(badge.get("issued_at_date"))

        # Skip pure backlog issues with no earned signal and no Credly match
        if not badge and not issued and not field(body, "Date Certified", "Earned Date"):
            continue

        issuer = issuer or "Unknown"
        issued = issued or "N/A"
        expiration = expiration or "N/A"
        status = status_for(title, expiration if expiration != "N/A" else None)

        name = re.sub(r"\s*\(.*?\)\s*$", "", title).strip() or "Unknown"
        url = f"https://github.com/jacob-kraniak/cybersecurity-certification-tracker/issues/{number}"
        if badge and badge.get("id"):
            credly_url = f"https://www.credly.com/badges/{badge.get('id')}"
            notes = f"[Credly]({credly_url}) • [Issue #{number}]({url})"
        else:
            notes = f"[Issue #{number}]({url})"

        rows.append(
            {
                "issued": issued,
                "line": f"| [{name}]({url}) | {issuer} | {status} | {issued} | {expiration} | {notes} |",
            }
        )

    # Credly badges with no tracker issue still appear (earned SoT)
    for b in badges:
        bid = b.get("id")
        if not bid or bid in used_badge_ids:
            continue
        used_badge_ids.add(bid)
        template = b.get("badge_template") or {}
        name = template.get("name") or "Unknown"
        issuer = issuer_from_badge(b) or "Unknown"
        issued = parse_date(b.get("issued_at_date")) or "N/A"
        credly_url = f"https://www.credly.com/badges/{bid}"
        rows.append(
            {
                "issued": issued,
                "line": f"| {name} | {issuer} | Active | {issued} | N/A | [Credly]({credly_url}) |",
            }
        )

    rows.sort(key=lambda r: issued_sort_key(r["issued"]), reverse=True)
    lines = [r["line"] for r in rows]

    table_rows = (
        "\n".join(lines)
        if lines
        else "| No earned Credly certifications found | - | - | - | - | - |"
    )

    content = Path("README.md").read_text(encoding="utf-8")
    new_table = f"""### Certification Details

| Certification | Issuer | Status | Issued | Expiration | Notes |
|---------------|--------|--------|--------|------------|-------|
{table_rows}
"""

    content = re.sub(
        r"### Certification Details[\s\S]*?(?=### Ongoing Journey|### The Book of Secret Knowledge|## 🌐 Socials)",
        new_table + "\n",
        content,
    )
    Path("README.md").write_text(content, encoding="utf-8")
    print(f"README updated with {len(lines)} Certification Details rows.")


if __name__ == "__main__":
    main()
