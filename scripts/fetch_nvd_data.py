import os
import requests

# Directory to store downloaded files
DATA_DIR = "data"

# Official URLs
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ✅ WORKING Exploit-DB source (GitLab mirror)
EXPLOIT_DB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

def download_file(url, dest):
    """Download a file from the URL to the destination path."""
    print(f"🔽 Downloading: {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        with open(dest, 'wb') as f:
            f.write(response.content)
        print(f"✅ Saved to: {dest}")
    except requests.exceptions.HTTPError as http_err:
        print(f"❌ HTTP error: {http_err}")
    except Exception as err:
        print(f"❌ Unexpected error: {err}")

def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    # Download vulnerability feeds
    download_file(NVD_URL, os.path.join(DATA_DIR, "nvd_modified.json.gz"))
    download_file(CISA_URL, os.path.join(DATA_DIR, "cisa_kev.json"))
    download_file(EXPLOIT_DB_URL, os.path.join(DATA_DIR, "exploitdb.csv"))

    print("🏁 All downloads attempted.")

if __name__ == "__main__":
    main()
