#!/usr/bin/env python3
"""Update README Active Badges from filtered_badges.json (preferred) or legacy BADGE_DATA argv."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import requests


def sanitize_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", name).lower() + ".png"


def download_badge_image(image_url: str, filename: str) -> str:
    try:
        response = requests.get(image_url, timeout=15)
        if response.status_code == 200:
            path = Path("images") / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(response.content)
            print(f"Downloaded {filename}")
            return str(path).replace("\\", "/")
        print(f"Failed to download {image_url} ({response.status_code})")
        return image_url
    except Exception as e:
        print(f"Error downloading {image_url}: {e}")
        return image_url


def load_badges() -> list[dict]:
    """Prefer filtered_badges.json; fall back to legacy argv BADGE_DATA."""
    json_path = Path("filtered_badges.json")
    if json_path.exists():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [b for b in data if isinstance(b, dict)]
        if isinstance(data, dict) and isinstance(data.get("badges"), list):
            return [b for b in data["badges"] if isinstance(b, dict)]

    badge_data = sys.argv[1] if len(sys.argv) > 1 else ""
    badges: list[dict] = []
    if not badge_data.strip():
        return badges
    for item in [x.strip() for x in badge_data.split(";;") if x.strip()]:
        # Fields are image|name|url — do NOT split on bare ';' inside names
        parts = [p.strip() for p in item.split("|")]
        if len(parts) >= 3 and parts[0] and parts[1] and not parts[0].startswith(("null", ";")):
            badges.append(
                {
                    "image_url": parts[0],
                    "name": parts[1],
                    "url": parts[2],
                    "id": parts[3] if len(parts) > 3 else parts[1],
                }
            )
    return badges


def dedupe(badges: list[dict]) -> list[dict]:
    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    out: list[dict] = []
    for b in badges:
        bid = str(b.get("id") or "").strip().lower()
        name = str(b.get("name") or "").strip()
        key = re.sub(r"[^a-z0-9]+", "", name.lower())
        if bid and bid in seen_ids:
            continue
        if key and key in seen_names:
            continue
        if bid:
            seen_ids.add(bid)
        if key:
            seen_names.add(key)
        if name and b.get("image_url"):
            out.append(b)
    return out


def main() -> None:
    badges = dedupe(load_badges())
    print(f"Parsed {len(badges)} unique badges")
    print(f"Badges: {[b.get('name') for b in badges]}")

    Path("images").mkdir(parents=True, exist_ok=True)

    badge_md = '### Active Badges\n\n<p align="center">\n'
    for b in badges[:8]:
        name = b["name"]
        url = b.get("url") or "https://www.credly.com/users/jacob-kraniak/badges"
        image_url = b["image_url"]
        filename = sanitize_filename(name)
        local_path = download_badge_image(image_url, filename)
        badge_md += (
            f'  <a href="{url}">\n'
            f'    <img src="{local_path}" alt="{name}" width="180" style="margin: 8px;" />\n'
            f"  </a>\n"
        )
    badge_md += "</p>\n\n"

    content = Path("README.md").read_text(encoding="utf-8")
    content = re.sub(
        r'### Active Badges\s*\n*(?:<p align="center">[\s\S]*?</p>\s*)*',
        "",
        content,
        flags=re.IGNORECASE,
    )

    if "### Certification Details" in content:
        new_content = re.sub(
            r"(### Certification Details)",
            badge_md + r"\1",
            content,
            count=1,
        )
    else:
        new_content = content + "\n" + badge_md

    Path("README.md").write_text(new_content, encoding="utf-8")
    print(f"Updated README with {len(badges)} Active Badges")


if __name__ == "__main__":
    main()
