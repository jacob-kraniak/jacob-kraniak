import sys

if len(sys.argv) > 1 and sys.argv[1]:
    image_url, name, url = sys.argv[1].split('|')
else:
    image_url = "https://raw.githubusercontent.com/jacob-kraniak/jacob-kraniak/main/images/comptia-server-certification.4.png"
    name = "CompTIA Server+"
    url = "https://www.credly.com/badges/1fc6fa72-65b5-4d96-bf02-88a27b0e71e2/public_url"

with open("README.md", "r", encoding="utf-8") as f:
    content = f.read()

# Replace the Active Badge section
new_badge = f"""### Active Badge
<p align="center">
  <a href="{url}">
    <img src="{image_url}" alt="{name}" width="150" />
  </a>
</p>
"""

start = content.find("### Active Badge")
end = content.find("### Certification Details", start)

if start != -1 and end != -1:
    new_content = content[:start] + new_badge + content[end:]
    with open("README.md", "w", encoding="utf-8") as f:
        f.write(new_content)
    print(f"✅ Updated Active Badge to: {name}")
