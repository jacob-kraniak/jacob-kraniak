import sys
import os
import re
import requests

def sanitize_filename(name):
    return re.sub(r'[^a-zA-Z0-9._-]+', '_', name).lower() + '.png'

def download_badge_image(image_url, filename):
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

# Parse badges from workflow input
badge_data = sys.argv[1] if len(sys.argv) > 1 else ''
badges = []
if badge_data.strip():
    for item in [x.strip() for x in badge_data.split(';;') if x.strip()]:
        # Handle possible malformed separators
        parts = [p.strip() for p in re.split(r'[|;]', item) if p.strip()]
        if len(parts) >= 3:
            image_url = parts[0]
            name = parts[1]
            url = parts[2]
            if image_url and name and not image_url.startswith(('null', ';')):
                badges.append((image_url, name, url))
        elif len(parts) == 2:
            # Fallback
            pass
print(f'Parsed {len(badges)} unique badges')

os.makedirs('images', exist_ok=True)

# Build new clean markdown for Active Badges
badge_md = '### Active Badges\n\n<p align="center">\n'
for image_url, name, url in badges[:6]:  # Limit to avoid clutter
    filename = sanitize_filename(name)
    local_path = download_badge_image(image_url, filename)
    badge_md += f'  <a href="{url}">\n    <img src="{local_path}" alt="{name}" width="180" style="margin: 8px;" />\n  </a>\n'
badge_md += '</p>\n\n'

# Load README
with open('README.md', 'r', encoding='utf-8') as f:
    content = f.read()

# Robust replacement: remove ALL existing Active Badges sections and insert one clean one before Certification Details
# First, remove existing Active Badges blocks
content = re.sub(r'### Active Badges\s*\n*(?:<p align="center">[\s\S]*?</p>\s*)*', '', content, flags=re.IGNORECASE | re.DOTALL)

# Insert the new one before Certification Details
if '### Certification Details' in content:
    new_content = re.sub(
        r'(### Certification Details)',
        badge_md + r'\1',
        content,
        count=1
    )
else:
    new_content = content + '\n' + badge_md

with open('README.md', 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f'✅ Updated README with {len(badges)} Active Badges section (deduplicated)')
print(f'Badges: {[name for _, name, _ in badges]}')
