import json
import requests
import os

MERGED_JSON_PATH = "data/merged_vulnerabilities.json"
OUTPUT_PATH = "data/merged_vulnerabilities_with_github_poc.json"
LOCAL_FALLBACK_PATH = "data/github_pocs.json"

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def fetch_github_pocs(cve_ids):
    print("🔄 Fetching PoC-in-GitHub entries per CVE...")
    base_url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
    poc_dict = {}

    for cve_id in cve_ids:
        year = cve_id.split("-")[1]
        url = f"{base_url}/{year}/{cve_id}.json"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                poc_dict[cve_id] = data.get("pocs", [])
        except requests.RequestException:
            continue
    return poc_dict

def enrich_with_pocs(vulns, poc_dict):
    for vuln in vulns:
        cve_id = vuln.get("cve_id", "").strip().upper()
        if cve_id in poc_dict:
            vuln["github_pocs"] = poc_dict[cve_id]
    return vulns

def main():
    if not os.path.exists(MERGED_JSON_PATH):
        raise FileNotFoundError(f"❌ {MERGED_JSON_PATH} does not exist.")

    raw_data = load_json(MERGED_JSON_PATH)

    if isinstance(raw_data, dict):
        vulnerabilities = list(raw_data.values())
    else:
        vulnerabilities = raw_data

    cve_ids = [v.get("cve_id", "").strip().upper() for v in vulnerabilities if v.get("cve_id")]
    poc_dict = fetch_github_pocs(cve_ids)
    save_json(poc_dict, LOCAL_FALLBACK_PATH)

    enriched = enrich_with_pocs(vulnerabilities, poc_dict)
    save_json(enriched, OUTPUT_PATH)
    print(f"✅ Enriched data saved to {OUTPUT_PATH} ({len(enriched)} entries)")

if __name__ == "__main__":
    main()
