import json
import gzip
import csv
import requests
import os
from collections import defaultdict

# === URLs ===
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_CSV_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/main/files_exploits.csv"

# === Output Path ===
OUTPUT_PATH = "data/merged_vulnerabilities.json"
os.makedirs("data", exist_ok=True)

# === Merged data structure ===
merged_data = defaultdict(dict)

# --- Fetchers ---

def fetch_nvd_data(url):
    print("🔄 Downloading NVD data...")
    response = requests.get(url)
    gz_path = "data/nvd_2024.json.gz"
    with open(gz_path, "wb") as f:
        f.write(response.content)
    with gzip.open(gz_path, 'rt', encoding='utf-8') as f:
        return json.load(f)

def fetch_cisa_data(url):
    print("🔄 Downloading CISA KEV data...")
    return requests.get(url).json().get("vulnerabilities", [])

def fetch_exploitdb_data(url):
    print("🔄 Downloading Exploit-DB CSV...")
    response = requests.get(url)
    lines = response.content.decode("utf-8").splitlines()
    return list(csv.DictReader(lines))

# --- Parsers ---

def parse_nvd(data):
    print("🔍 Parsing NVD...")
    for item in data.get("CVE_Items", []):
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        entry = merged_data[cve_id]
        entry["cve_id"] = cve_id
        entry["description"] = item["cve"]["description"]["description_data"][0]["value"]
        cvss = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {})
        entry["severity"] = cvss.get("baseSeverity")
        entry["attack_vector"] = cvss.get("attackVector")
        entry["impact"] = cvss.get("impactScore")
        entry["affected_products"] = list({
            cpe["cpe23Uri"]
            for node in item.get("configurations", {}).get("nodes", [])
            for cpe in node.get("cpe_match", [])
            if "cpe23Uri" in cpe
        })
        refs = item["cve"]["references"]["reference_data"]
        entry["patch_available"] = any(
            "patch" in ref.get("tags", []) or
            "patch" in ref.get("description", "").lower()
            for ref in refs
        )

def parse_cisa(cisa_data):
    print("🔍 Parsing CISA KEV...")
    for vuln in cisa_data:
        cve_id = vuln.get("cveID")
        if cve_id:
            entry = merged_data[cve_id]
            entry["exploited"] = True
            entry["cisa_kev"] = {
                "dateAdded": vuln.get("dateAdded"),
                "notes": vuln.get("notes"),
                "mitigations": vuln.get("requiredAction"),
                "vendorProject": vuln.get("vendorProject"),
                "product": vuln.get("product")
            }

def parse_exploitdb(exploitdb_data):
    print("🔍 Parsing Exploit-DB...")
    for row in exploitdb_data:
        cve_id = row.get("cve")
        if cve_id:
            entry = merged_data[cve_id]
            entry.setdefault("exploitdb_exploits", []).append({
                "exploit_id": row.get("id"),
                "title": row.get("description"),
                "url": f"https://www.exploit-db.com/exploits/{row.get('id')}",
                "platform": row.get("platform"),
                "type": row.get("type"),
                "date": row.get("date")
            })

# --- Run Pipeline ---

nvd = fetch_nvd_data(NVD_URL)
cisa = fetch_cisa_data(CISA_URL)
exploitdb = fetch_exploitdb_data(EXPLOITDB_CSV_URL)

parse_nvd(nvd)
parse_cisa(cisa)
parse_exploitdb(exploitdb)

# Export merged JSON
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(merged_data, f, indent=2)

print(f"✅ Done. Merged vulnerability data written to {OUTPUT_PATH} ({len(merged_data)} CVEs)")
