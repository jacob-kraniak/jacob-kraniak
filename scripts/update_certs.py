import sys

table_rows = sys.argv[1] if len(sys.argv) > 1 else "| No active certifications found. | - | - | - | - | - |"

readme_path = "README.md"

with open(readme_path, "r", encoding="utf-8") as f:
    content = f.read()

start_marker = "### Certification Details"
end_marker = "### Ongoing Journey"

start_idx = content.find(start_marker)
end_idx = content.find(end_marker, start_idx)

if start_idx != -1 and end_idx != -1:
    # Keep everything up to the header row, then insert new rows
    header_end = content.find("\n\n", start_idx) + 2 if "\n\n" in content[start_idx:end_idx] else start_idx + content[start_idx:end_idx].find("\n|") + 1
    
    new_section = content[:header_end] + table_rows.strip() + "\n" + content[end_idx:]
    
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(new_section)
    print("✅ README updated successfully")
else:
    print("⚠️ Table markers not found")
