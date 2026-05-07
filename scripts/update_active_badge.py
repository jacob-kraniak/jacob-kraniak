import sys
import os
import re
import requests

def sanitize_filename(name):
    """Clean name for filename."""
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', name).lower() + '.png'

def download_badge_image(image_url, filename):
    """Download high-res badge and save locally."""
    try:
        response = requests.get(image_url, timeout=10)
        if response.status_code == 200:
            with open(os.path.join('images', filename), 'wb') as f:
                f.write(response.content)
            print(f'Downloaded high-res {filename}')
            return f'images/{filename}'
        else:
            print(f'Failed to download {image_url}')
            return image_url
    except Exception as e:
        print(f'Error downloading {image_url}: {e}')
        return image_url

# Parse badges from workflow (or fallback to empty)
if len(sys.argv) > 1 and sys.argv[1].strip():
    badge_str = sys.argv[1]
    badges = []
    for item in [x.strip() for x in badge_str.split(';;') if x.strip()]:
        parts = [p.strip() for p in item.split('|', 2)]
        if len(parts) == 3:
            badges.append(parts)
else:
    badges = []
    print("Warning: No badge data received from workflow")

os.makedirs('images', exist_ok=True)

# Build markdown
badge_md = '### Active Badges\n\n<p align="center">\n'
for image_url, name, url in badges[:8]:  # up to 8 badges
    if not image_url or image_url.startswith('null'):
        continue
    filename = sanitize_filename(name)
    local_path = download_badge_image(image_url, filename)
    badge_md += f'  <a href="{url}">\n    <img src="{local_path}" alt="{name}" width="180" style="margin: 8px;" />\n  </a>\n'
badge_md += '</p>\n\n'

# Read README
with open('README.md', 'r', encoding='utf-8') as f:
    content = f.read()

# Robust section replacement (handles singular/plural and broken sections)
match = re.search(r'### Active Badge[s]?\s*\n.*?(?=\n### Certification Details|\n##|\n#|$)', content, re.DOTALL | re.IGNORECASE)

if match:
    new_content = content[:match.start()] + badge_md + content[match.end():]
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f'✅ Updated {len(badges)} Active Badges with high-res local images')
else:
    print('⚠️  Active Badges section not found — appending at Certifications')
    # Fallback: insert before Certification Details
    content = re.sub(r'(### Certification Details)', badge_md + r'\1', content, count=1)
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(content)
    print('✅ Inserted Active Badges section')

print(f"Processed badges: {[name for _, name, _ in badges]}")
