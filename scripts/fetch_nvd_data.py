import os
import requests

DATA_DIR = "data"
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOIT_DB_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"

def download_file(url, dest):
    print(f"Downloading: {url}")
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(dest, 'wb') as f:
            f.write(response.content)
        print(f"Saved to: {dest}")
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            print(f"❗ Warning: Resource not found at {url} (404). Skipping download.")
        else:
            print(f"❌ HTTP error occurred: {http_err}")
            raise
    except Exception as err:
        print(f"❌ Error occurred: {err}")
        raise

def main():
    os.makedirs(DATA_DIR, exist_ok=True)

    # Download NVD feed
    download_file(NVD_URL, os.path.join(DATA_DIR, "nvd_modified.json.gz"))

    # Download CISA KEV catalog
    download_file(CISA_URL, os.path.join(DATA_DIR, "cisa_kev.json"))

    # Download Exploit-DB CSV
    download_file(EXPLOIT_DB_URL, os.path.join(DATA_DIR, "exploitdb.csv"))

    print("✅ All vulnerability sources fetched successfully.")

if __name__ == "__main__":
    main()