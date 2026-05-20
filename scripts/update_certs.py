#!/usr/bin/env python3
import sys
import re

table_rows = sys.argv[1] if len(sys.argv) > 1 else ''

with open('README.md', 'r', encoding='utf-8') as f:
    content = f.read()

new_table = f'''### Certification Details

| Certification | Issuer | Status | Issued | Expiration | Notes |
|---------------|--------|--------|--------|------------|-------|
{table_rows}'''

# Replace the table section
content = re.sub(
    r'### Certification Details[\s\S]*?(?=### Ongoing Journey|### The Book of Secret Knowledge|## 🌐 Socials)',
    new_table + '\n',
    content
)

with open('README.md', 'w', encoding='utf-8') as f:
    f.write(content)
print('README updated with dynamic cert table.')