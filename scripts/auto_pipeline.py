import subprocess
from update_nvd import fetch_nvd_data  # You’d create this
from merge_vulnerabilities import merge_data
from enrich_with_github_pocs import enrich_data
from json_to_sqlite import json_to_sqlite

def main():
    print("Fetching latest NVD data...")
    fetch_nvd_data()

    print("Merging vulnerabilities...")
    merge_data()

    print("Enriching with GitHub PoCs...")
    enrich_data()

    print("Saving to SQLite...")
    json_to_sqlite()

    print("✅ Pipeline complete.")

if __name__ == "__main__":
    main()
