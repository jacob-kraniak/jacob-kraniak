import sys

# Dynamic rows from GitHub Action (only Active certs)
dynamic_rows = sys.argv[1] if len(sys.argv) > 1 else ""

readme_path = "README.md"

with open(readme_path, "r", encoding="utf-8") as f:
    content = f.read()

start_marker = "### Certification Details"
end_marker = "### Ongoing Journey"

start_idx = content.find(start_marker)
end_idx = content.find(end_marker, start_idx)

if start_idx != -1 and end_idx != -1:
    new_table = """### Certification Details

| Certification | Issuer | Status | Issued | Expiration | Notes |
|---------------|--------|--------|--------|------------|-------|
"""

    # Add only Active rows (clean formatting)
    if dynamic_rows.strip():
        new_table += dynamic_rows.strip() + "\n"
    else:
        new_table += "| No active certifications at the moment | - | Active | - | - | Check [Project Board](https://github.com/users/jacob-kraniak/projects/3) |\n"

    new_table += "\n### Ongoing Journey"

    # Replace section
    new_content = content[:start_idx] + new_table + content[end_idx + len(end_marker):]

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    print("✅ Profile README updated — showing only Active certs")
else:
    print("⚠️ Could not find table markers")
