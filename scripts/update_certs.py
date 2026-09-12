#!/usr/bin/env python3
"""Rebuild Certification Details from tracker issues enriched with Credly data."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def tokens(s: str) -> set[str]:
    stop = {"certification", "certified", "ce", "the", "in", "and", "of", "a"}
    return {t for t in norm(s).split() if len(t) > 1 and t not in stop}


def score_match(issue_title: str, badge_name: str) -> int:
    ti, tb = tokens(issue_title), tokens(badge_name)
    if not ti or not tb:
        return 0
    overlap = ti & tb
    # Require meaningful overlap (e.g. network, server, cybersecurity/cc, a+)
    if not overlap:
        return 0
    return len(overlap)


def issuer_from_badge(badge: dict) -> str:
    template = badge.get("badge_template") or {}
    issuer = template.get("issuer") or {}
    entities = issuer.get("entities") or []
    if entities:
        name = ((entities[0] or {}).get("entity") or {}).get("name")
        if name:
            return name
    return "Unknown"


def main() -> None:
    # Optional: rows passed as argv for backward compat — prefer files
    badges_path = Path("badges.json")
    issues_path = Path("tracker_issues.json")

    badges = []
    if badges_path.exists():
        raw = json.loads(badges_path.read_text(encoding="utf-8"))
        badges = [b for b in (raw.get("data") or []) if b.get("state") == "accepted" and b.get("badge_template")]

    issues = []
    if issues_path.exists():
        issues = json.loads(issues_path.read_text(encoding="utf-8"))

    # Map badge id -> badge
    by_id = {b.get("id"): b for b in badges if b.get("id")}

    rows: list[str] = []
    used_badge_ids: set[str] = set()

    # Prefer issues that already reference a Credly badge id, then fuzzy title match
    for issue in sorted(issues, key=lambda i: i.get("updated_at") or "", reverse=True):
        body = issue.get("body") or ""
        title = issue.get("title") or ""
        number = issue.get("number")
        m = re.search(r"\*\*Credly Badge ID\*\*:\s*([a-f0-9-]{36})", body, re.I)
        badge = by_id.get(m.group(1)) if m else None

        if not badge:
            # fuzzy match against remaining badges
            best, best_score = None, 0
            for b in badges:
                bid = b.get("id")
                if bid in used_badge_ids:
                    continue
                name = (b.get("badge_template") or {}).get("name") or ""
                sc = score_match(title, name)
                if sc > best_score:
                    best, best_score = b, sc
            # Need at least 2 overlapping tokens OR one strong token like server+/network+/cybersecurity
            if best and best_score >= 1:
                bname = (best.get("badge_template") or {}).get("name") or ""
                bname_toks = tokens(bname)
                strong = tokens(title) & {"server", "network", "cybersecurity", "cc"}
                a_plus = bool(re.search(r"\ba\+", title.lower()) and re.search(r"\ba\+", bname.lower()))
                if best_score >= 2 or (strong & bname_toks) or a_plus:
                    badge = best

        if not badge:
            continue

        bid = badge.get("id")
        if bid in used_badge_ids:
            continue
        used_badge_ids.add(bid)

        template = badge.get("badge_template") or {}
        issuer = issuer_from_badge(badge)
        issued = badge.get("issued_at_date") or "N/A"
        # Prefer issue title (human) when present
        name = re.sub(r"\s*\(.*?\)\s*$", "", title).strip() or template.get("name") or "Unknown"
        url = f"https://github.com/jacob-kraniak/cybersecurity-certification-tracker/issues/{number}"
        credly_url = f"https://www.credly.com/badges/{bid}"
        rows.append(
            f"| [{name}]({url}) | {issuer} | Active | {issued} | N/A | [Credly]({credly_url}) • [Issue #{number}]({url}) |"
        )

    # Any Credly badges not matched to an issue still appear (Credly is SoT for earned)
    for b in badges:
        bid = b.get("id")
        if not bid or bid in used_badge_ids:
            continue
        used_badge_ids.add(bid)
        template = b.get("badge_template") or {}
        name = template.get("name") or "Unknown"
        issuer = issuer_from_badge(b)
        issued = b.get("issued_at_date") or "N/A"
        credly_url = f"https://www.credly.com/badges/{bid}"
        rows.append(
            f"| {name} | {issuer} | Active | {issued} | N/A | [Credly]({credly_url}) |"
        )

    table_rows = "\n".join(rows) if rows else "| No earned Credly certifications found | - | - | - | - | - |"

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
    print(f"README updated with {len(rows)} Certification Details rows.")


if __name__ == "__main__":
    main()
