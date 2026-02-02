# vibe-coded using M365 Copilot

import whois
import dns.resolver
import requests
import csv
import sys
from datetime import datetime

# Default domain list (used if no CSV provided)
default_domains = []

# Check if CSV path is provided as argument
if len(sys.argv) > 1:
    csv_path = sys.argv[1]
    try:
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            domains = [row[0].strip() for row in reader if row]
        print(f"✅ Loaded {len(domains)} domains from {csv_path}")
    except Exception as e:
        print(f"⚠️ Error reading CSV file: {e}")
        print("Using default domain list instead.")
        domains = default_domains
else:
    domains = default_domains
    print("ℹ️ No CSV provided. Using default domain list.")

# Output CSV file
output_file = "domain_report.csv"

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrant": w.get("org", "N/A"),
            "registrar": w.get("registrar", "N/A"),
            "creation_date": str(w.get("creation_date", "N/A")),
            "expiration_date": str(w.get("expiration_date", "N/A"))
        }
    except:
        return {"registrant": "Error", "registrar": "Error", "creation_date": "Error", "expiration_date": "Error"}

def get_dns(domain):
    records = {"A": [], "MX": [], "NS": [], "SPF": "None", "DKIM": "None"}
    try:
        a_record = dns.resolver.resolve(domain, 'A')
        records["A"] = [ip.to_text() for ip in a_record]
    except:
        records["A"] = ["None"]
    try:
        mx_record = dns.resolver.resolve(domain, 'MX')
        records["MX"] = [mx.to_text() for mx in mx_record]
    except:
        records["MX"] = ["None"]
    try:
        ns_record = dns.resolver.resolve(domain, 'NS')
        records["NS"] = [ns.to_text() for ns in ns_record]
    except:
        records["NS"] = ["None"]
    # Check SPF/DKIM in TXT records
    try:
        txt_record = dns.resolver.resolve(domain, 'TXT')
        for txt in txt_record:
            txt_str = txt.to_text()
            if "spf" in txt_str.lower():
                records["SPF"] = txt_str
            if "dkim" in txt_str.lower():
                records["DKIM"] = txt_str
    except:
        pass
    return records

def check_landing_page(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=5)
        status = r.status_code
        title = "N/A"
        if "<title>" in r.text:
            title = r.text.split("<title>")[1].split("</title>")[0]
        return {"status": status, "title": title}
    except:
        return {"status": "Unreachable", "title": "N/A"}

def calculate_risk(whois_data, dns_data, page_data):
    risk_score = 0
    if page_data["status"] == "Unreachable":
        risk_score += 2
    if whois_data["registrant"] == "Error":
        risk_score += 2
    if "None" in dns_data["A"]:
        risk_score += 1
    if dns_data["SPF"] == "None":
        risk_score += 1
    if risk_score >= 4:
        return "High"
    elif risk_score >= 2:
        return "Medium"
    else:
        return "Low"

# Write CSV
with open(output_file, mode="w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    writer.writerow([
        "Domain", "Landing Page Status", "Page Title",
        "Registrant", "Registrar", "Creation Date", "Expiration Date",
        "A Records", "MX Records", "NS Records", "SPF", "DKIM", "Risk Level"
    ])

    for domain in domains:
        print(f"Processing {domain}...")
        whois_data = get_whois(domain)
        dns_data = get_dns(domain)
        page_data = check_landing_page(domain)
        risk_level = calculate_risk(whois_data, dns_data, page_data)

        writer.writerow([
            domain, page_data["status"], page_data["title"],
            whois_data["registrant"], whois_data["registrar"],
            whois_data["creation_date"], whois_data["expiration_date"],
            ", ".join(dns_data["A"]), ", ".join(dns_data["MX"]), ", ".join(dns_data["NS"]),
            dns_data["SPF"], dns_data["DKIM"], risk_level
        ])

print(f"✅ Report generated: {output_file}")
