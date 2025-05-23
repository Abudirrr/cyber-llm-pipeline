import json
import requests
import os

# URLs and file paths
POC_FEED_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/main/dist/pocs.json"
MERGED_JSON_PATH = "data/merged_vulnerabilities.json"
OUTPUT_PATH = "data/merged_vulnerabilities_with_github_poc.json"
LOCAL_FALLBACK_PATH = "data/github_poc_cache.json"  # optional cache file

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def fetch_github_pocs():
    print("🔄 Fetching PoC-in-GitHub feed...")
    try:
        response = requests.get(POC_FEED_URL)
        response.raise_for_status()
        data = response.json()
        save_json(data, LOCAL_FALLBACK_PATH)  # Save to cache
        return data
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP error fetching PoC-in-GitHub feed: {e}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error: {e}")
    # Fallback if download fails
    if os.path.exists(LOCAL_FALLBACK_PATH):
        print(f"⚠️ Using cached PoC data from {LOCAL_FALLBACK_PATH}")
        return load_json(LOCAL_FALLBACK_PATH)
    raise RuntimeError("Failed to fetch PoC-in-GitHub feed and no cache available.")

def build_poc_dict(poc_entries):
    poc_dict = {}
    for entry in poc_entries:
        cve_id = entry.get("cve_id", "").strip().upper()
        if cve_id:
            poc_dict.setdefault(cve_id, []).append({
                "url": entry.get("url"),
                "description": entry.get("description"),
                "author": entry.get("author"),
                "date": entry.get("date")
            })
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

    vulnerabilities = load_json(MERGED_JSON_PATH)
    poc_entries = fetch_github_pocs()
    poc_dict = build_poc_dict(poc_entries)
    enriched = enrich_with_pocs(vulnerabilities, poc_dict)
    save_json(enriched, OUTPUT_PATH)
    print(f"✅ Enriched data saved to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
