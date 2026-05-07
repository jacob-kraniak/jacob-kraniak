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
            print(f'Downloaded high-res {filename} (better quality)')
            return f'images/{filename}'
        else:
            print(f'Failed to download {image_url}')
            return image_url
    except Exception as e:
        print(f'Error downloading: {e}')
        return image_url

if len(sys.argv) > 1 and sys.argv[1]:
    badge_str = sys.argv[1]
    badges = []
    for item in [x for x in badge_str.split(';;') if x]:
        parts = [p.strip() for p in item.split('|', 2)]
        if len(parts) == 3:
            badges.append(parts)
else:
    badges = [("https://images.credly.com/images/ff6cecf9-8aca-43c5-8070-44023bb55417/blob", "CompTIA Server+", "https://www.credly.com/badges/1fc6fa72-65b5-4d96-bf02-88a27b0e71e2/public_url")]

os.makedirs('images', exist_ok=True)

badge_md = '### Active Badges\n\n<p align="center">\n'
for image_url, name, url in badges[:6]:
    filename = sanitize_filename(name)
    local_path = download_badge_image(image_url, filename)
    badge_md += f'  <a href="{url}">\n    <img src="{local_path}" alt="{name}" width="180" style="margin: 8px;" />\n  </a>\n'
badge_md += '</p>\n'

with open('README.md', 'r', encoding='utf-8') as f:
    content = f.read()

start = content.find('### Active Badge')
end = content.find('### Certification Details', start) if start != -1 else -1

if start != -1 and end != -1:
    new_content = content[:start] + badge_md + content[end:]
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f'✅ Updated {len(badges)} Active Badges (local high-res images)')
else:
    print('Section not found')