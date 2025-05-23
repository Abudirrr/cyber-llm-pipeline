import json
import csv
import os
from collections import defaultdict

# Base folder where your datasets are
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUTPUT_FILE = os.path.join(BASE_DIR, "master_dataset.jsonl")

# Helper functions
def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_csv(path):
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))

# Dictionary to accumulate data by CVE ID
combined = defaultdict(lambda: {"sources": []})

# Load merged enriched JSON (core base)
try:
    enriched = load_json(os.path.join(BASE_DIR, "merged_vulnerabilities_enriched.json"))
    if isinstance(enriched, dict):
        for cve, entry in enriched.items():
            cve_id = entry.get("cve_id") or entry.get("id") or cve
            if cve_id:
                combined[cve_id].update(entry)
                combined[cve_id]["sources"].append("enriched")
    else:
        print("⚠️ merged_vulnerabilities_enriched.json is not a dictionary.")
except FileNotFoundError:
    print("⚠️ merged_vulnerabilities_enriched.json not found.")

# Load PacketStorm exploits
try:
    packetstorm = load_json(os.path.join(BASE_DIR, "packetstorm_exploits.json"))
    for entry in packetstorm:
        cve = entry.get("cve") or entry.get("cve_id")
        if cve and cve in combined:
            combined[cve]["packetstorm_exploit"] = entry
            combined[cve]["sources"].append("packetstorm")
except FileNotFoundError:
    print("⚠️ packetstorm_exploits.json not found.")

# Load high_unpatched.csv
try:
    high = load_csv(os.path.join(BASE_DIR, "high_unpatched.csv"))
    for row in high:
        cve = row.get("CVE ID") or row.get("cve_id")
        if cve and cve in combined:
            combined[cve]["high_unpatched"] = True
            combined[cve]["sources"].append("high_unpatched_csv")
except FileNotFoundError:
    print("⚠️ high_unpatched.csv not found.")

# Load GitHub PoC summary
try:
    summary = load_csv(os.path.join(BASE_DIR, "summary_with_github_pocs.csv"))
    for row in summary:
        cve = row.get("CVE ID") or row.get("cve_id")
        if cve and cve in combined:
            combined[cve]["github_poc_summary"] = row
            combined[cve]["sources"].append("github_poc_summary_csv")
except FileNotFoundError:
    print("⚠️ summary_with_github_pocs.csv not found.")

# Load critical_with_poc.csv
try:
    critical = load_csv(os.path.join(BASE_DIR, "critical_with_poc.csv"))
    for row in critical:
        cve = row.get("CVE ID") or row.get("cve_id")
        if cve and cve in combined:
            combined[cve]["critical_with_poc"] = True
            combined[cve]["sources"].append("critical_with_poc_csv")
except FileNotFoundError:
    print("⚠️ critical_with_poc.csv not found.")

# Write to master_dataset.jsonl
with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    for cve_id, data in combined.items():
        data["cve_id"] = cve_id
        json.dump(data, out)
        out.write("\n")

print(f"✅ Done. {len(combined)} CVEs written to {OUTPUT_FILE}")
