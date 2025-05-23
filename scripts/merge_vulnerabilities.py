import json, gzip, csv, requests
from collections import defaultdict

# URLs to fetch data from
nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz"
cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
exploitdb_csv_url = "https://raw.githubusercontent.com/offensive-security/exploitdb/main/files_exploits.csv"

# Dictionary to merge data by CVE ID
merged_data = defaultdict(dict)

# --- Fetchers ---

def fetch_nvd_data(url):
    response = requests.get(url)
    with open("nvd_2024.json.gz", "wb") as f:
        f.write(response.content)
    with gzip.open("nvd_2024.json.gz", 'rt', encoding='utf-8') as f:
        return json.load(f)

def fetch_cisa_data(url):
    return requests.get(url).json()["vulnerabilities"]

def fetch_exploitdb_data(url):
    response = requests.get(url)
    lines = response.content.decode("utf-8").splitlines()
    return list(csv.DictReader(lines))

# --- Parsers ---

def parse_nvd(data):
    for item in data["CVE_Items"]:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        entry = merged_data[cve_id]
        entry["id"] = cve_id
        entry["description"] = item["cve"]["description"]["description_data"][0]["value"]
        entry["severity"] = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity")
        entry["attack_vector"] = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("attackVector")
        entry["impact"] = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("impactScore")
        entry["affected_products"] = list({
            cpe["cpe23Uri"]
            for node in item.get("configurations", {}).get("nodes", [])
            for cpe in node.get("cpe_match", [])
        })
        refs = item["cve"]["references"]["reference_data"]
        entry["patch_available"] = any(
            "patch" in ref.get("tags", []) or
            ("patch" in ref.get("description", "").lower())
            for ref in refs
        )

def parse_cisa(cisa_data):
    for vuln in cisa_data:
        cve_id = vuln.get("cveID")
        if cve_id:
            entry = merged_data[cve_id]
            entry["exploited"] = True
            entry["mitigation"] = vuln.get("notes")

def parse_exploitdb(exploitdb_data):
    for row in exploitdb_data:
        cve_id = row.get("cve")
        if cve_id:
            entry = merged_data[cve_id]
            entry["exploitdb_id"] = row.get("id")
            entry["poc_link"] = f"https://www.exploit-db.com/exploits/{row['id']}"

# --- Main Execution ---

print("🔄 Fetching and parsing NVD data...")
nvd = fetch_nvd_data(nvd_url)
print("✅ NVD data loaded.")

print("🔄 Fetching and parsing CISA KEV data...")
cisa = fetch_cisa_data(cisa_url)
print("✅ CISA data loaded.")

print("🔄 Fetching and parsing Exploit-DB data...")
exploitdb = fetch_exploitdb_data(exploitdb_csv_url)
print("✅ Exploit-DB data loaded.")

parse_nvd(nvd)
parse_cisa(cisa)
parse_exploitdb(exploitdb)

# Export to JSON
with open("merged_vulnerabilities.json", "w", encoding="utf-8") as f:
    json.dump(merged_data, f, indent=2)

print("✅ Merged data saved to 'merged_vulnerabilities.json'")
