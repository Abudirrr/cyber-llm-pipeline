import os
import requests

# Directory to store downloaded files
DATA_DIR = "data"

# Official URLs
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Primary and fallback Exploit-DB sources
EXPLOIT_DB_URLS = [
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",  # Often breaks
    "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",  # More stable
]

def download_file(url, dest):
    """Downloads a file and saves it to the destination path."""
    print(f"🔽 Downloading: {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        with open(dest, 'wb') as f:
            f.write(response.content)
        print(f"✅ Saved to: {dest}")
        return True
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            print(f"❗ 404 Not Found: {url}")
        else:
            print(f"❌ HTTP error: {http_err}")
        return False
    except Exception as err:
        print(f"❌ General error: {err}")
        return False

def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    # Download NVD
    download_file(NVD_URL, os.path.join(DATA_DIR, "nvd_modified.json.gz"))

    # Download CISA
    download_file(CISA_URL, os.path.join(DATA_DIR, "cisa_kev.json"))

    # Try all Exploit-DB URLs until one succeeds
    for url in EXPLOIT_DB_URLS:
        if download_file(url, os.path.join(DATA_DIR, "exploitdb.csv")):
            break
    else:
        print("⚠️ Could not fetch Exploit-DB CSV from any known source.")

    print("🏁 All downloads attempted.")

if __name__ == "__main__":
    main()
