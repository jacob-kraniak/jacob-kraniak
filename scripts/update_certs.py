import os
import sys

# Get the table rows from GitHub output
table_rows = sys.argv[1] if len(sys.argv) > 1 else "| No active certifications found. | - | - | - | - | - |"

readme_path = "README.md"

with open(readme_path, "r", encoding="utf-8") as f:
    content = f.read()

# Find the Certification Details table and replace the body
start_marker = "### Certification Details"
end_marker = "### Ongoing Journey"

start_idx = content.find(start_marker)
end_idx = content.find(end_marker)

if start_idx != -1 and end_idx != -1:
    # Keep header, replace rows
    header_end = content.find("\n\n", start_idx) + 2
    new_content = (
        content[:header_end] +
        table_rows +
        "\n" +
        content[end_idx:]
    )
    
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(new_content)
    print("✅ Successfully updated README.md with new cert rows")
else:
    print("⚠️ Could not find table markers")
