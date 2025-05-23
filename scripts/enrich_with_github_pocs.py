import json
import requests
import pandas as pd

# Load your merged vulnerability file
with open("merged_vulnerabilities.json", "r", encoding="utf-8") as f:
    merged_data = json.load(f)

# Correct URL for PoC-in-GitHub (NDJSON format)
github_poc_url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/dist/pocs.ndjson"

print("🔄 Fetching PoC-in-GitHub links...")
response = requests.get(github_poc_url)
lines = response.text.splitlines()

# Process line-by-line (NDJSON format)
print("🔗 Integrating GitHub PoCs...")
for line in lines:
    try:
        item = json.loads(line)
        cve_id = item.get("cve_id")
        if cve_id and cve_id in merged_data:
            if "github_poc_links" not in merged_data[cve_id]:
                merged_data[cve_id]["github_poc_links"] = []
            merged_data[cve_id]["github_poc_links"].append(item.get("repository"))
    except json.JSONDecodeError:
        continue  # skip malformed lines

# Save the enriched file
with open("merged_vulnerabilities_enriched.json", "w", encoding="utf-8") as f:
    json.dump(merged_data, f, indent=2)

print("✅ Enriched file saved as 'merged_vulnerabilities_enriched.json'")

# Optional: summary output to check
summary = []
for cve, data in merged_data.items():
    summary.append({
        "CVE ID": cve,
        "Severity": data.get("severity"),
        "Exploited": data.get("exploited"),
        "Patch Available": data.get("patch_available"),
        "GitHub PoC?": "✅" if "github_poc_links" in data else "❌"
    })

# Save summary to CSV
df = pd.DataFrame(summary)
df.to_csv("summary_with_github_pocs.csv", index=False)
print("📄 Summary saved to 'summary_with_github_pocs.csv'")
