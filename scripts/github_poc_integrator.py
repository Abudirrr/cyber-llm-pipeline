import json
import requests
import os
import time
import random

MERGED_JSON_PATH = "data/merged_vulnerabilities.json"
OUTPUT_PATH = "data/merged_vulnerabilities_with_github_poc.json"
LOCAL_FALLBACK_PATH = "data/github_pocs.json"

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def fetch_with_retries(url, retries=3, delay=2):
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            print(f"⚠️ Attempt {attempt + 1} failed for {url}: {e}")
            if attempt < retries - 1:
                time.sleep(delay + random.uniform(0, 2))  # Add jitter
            else:
                print(f"❌ Giving up on {url} after {retries} attempts.")
    return None

def fetch_github_pocs(cve_ids):
    if os.path.exists(LOCAL_FALLBACK_PATH):
        print("⚡ Using cached PoC data from previous run.")
        return load_json(LOCAL_FALLBACK_PATH)

    print("🔄 Fetching PoC-in-GitHub entries per CVE...")
    base_url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
    poc_dict = {}

    for cve_id in cve_ids:
        year = cve_id.split("-")[1]
        url = f"{base_url}/{year}/{cve_id}.json"

        response = fetch_with_retries(url)
        if response and response.status_code == 200:
            try:
                data = response.json()
                if isinstance(data, dict):
                    poc_dict[cve_id] = data.get("pocs", [])
                elif isinstance(data, list):
                    poc_dict[cve_id] = data
                    print(f"ℹ️ Used direct list for {cve_id} (non-standard format)")
                else:
                    print(f"⚠️ Unsupported format for {cve_id}: {type(data).__name__}")
            except Exception as e:
                print(f"⚠️ Failed to parse JSON for {cve_id}: {e}")
        else:
            print(f"⚠️ Could not retrieve data for {cve_id}")

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
    vulnerabilities = list(raw_data.values()) if isinstance(raw_data, dict) else raw_data

    cve_ids = [v.get("cve_id", "").strip().upper() for v in vulnerabilities if v.get("cve_id")]
    poc_dict = fetch_github_pocs(cve_ids)

    save_json(poc_dict, LOCAL_FALLBACK_PATH)  # Cache

    enriched = enrich_with_pocs(vulnerabilities, poc_dict)
    save_json(enriched, OUTPUT_PATH)

    print(f"✅ Enriched data saved to {OUTPUT_PATH} ({len(enriched)} entries)")

if __name__ == "__main__":
    main()
