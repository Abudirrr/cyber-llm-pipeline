import os
import requests

# Directory to save downloaded files
DATA_DIR = "data"

# Official source URLs
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Exploit-DB mirror via GitLab (more reliable than GitHub raw)
EXPLOIT_DB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

def download_file(url, dest):
    """Downloads a file from URL and saves it to the destination path."""
    print(f"🔽 Downloading: {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        with open(dest, 'wb') as f:
            f.write(response.content)
        print(f"✅ Saved to: {dest}")
    except requests.HTTPError as e:
        print(f"❌ HTTP error while downloading {url}:\n   {e}")
    except requests.RequestException as e:
        print(f"❌ Connection error while downloading {url}:\n   {e}")
    except Exception as e:
        print(f"❌ Unexpected error:\n   {e}")

def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    # Download files from all sources
    download_file(NVD_URL, os.path.join(DATA_DIR, "nvd_modified.json.gz"))
    download_file(CISA_URL, os.path.join(DATA_DIR, "cisa_kev.json"))
    download_file(EXPLOIT_DB_URL, os.path.join(DATA_DIR, "exploitdb.csv"))

    print("🏁 All vulnerability source downloads completed.")

if __name__ == "__main__":
    main()
