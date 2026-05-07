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

# === Parse badges from workflow ===
if len(sys.argv) > 1 and sys.argv[1].strip():
    badge_str = sys.argv[1]
    badges = []
    for item in [x.strip() for x in badge_str.split(';;') if x.strip()]:
        parts = [p.strip() for p in item.split('|', 2)]
        if len(parts) == 3 and parts[0] and not parts[0].startswith('null'):
            badges.append(parts)
    print(f"Parsed {len(badges)} badges from Credly")
else:
    badges = []
    print("Warning: No badge data from workflow")

os.makedirs('images', exist_ok=True)

# === Build new markdown ===
badge_md = '### Active Badges\n\n<p align="center">\n'
for image_url, name, url in badges[:8]:
    filename = sanitize_filename(name)
    local_path = download_badge_image(image_url, filename)
    badge_md += f'  <a href="{url}">\n    <img src="{local_path}" alt="{name}" width="180" style="margin: 8px;" />\n  </a>\n'
badge_md += '</p>\n\n'

# === Replace section in README ===
with open('README.md', 'r', encoding='utf-8') as f:
    content = f.read()

# More robust replacement
new_content = re.sub(
    r'### Active Badge[s]?\s*[\s\S]*?(?=### Certification Details)',
    badge_md,
    content,
    flags=re.IGNORECASE
)

if new_content == content:  # fallback
    new_content = re.sub(
        r'(### Certification Details)',
        badge_md + r'\1',
        content
    )

with open('README.md', 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f'✅ Successfully updated {len(badges)} Active Badges')
print(f"Badges: {[name for _, name, _ in badges]}")
