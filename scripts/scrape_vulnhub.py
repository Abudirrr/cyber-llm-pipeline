import requests
from bs4 import BeautifulSoup
import json
import re
import os

BASE_URL = "https://www.vulnhub.com"
LISTING_URL = "https://www.vulnhub.com/listings/"
OUTPUT_PATH = "data/vulnhub_vms.json"

def get_listing_pages(max_pages=5):
    urls = []
    for i in range(1, max_pages + 1):
        urls.append(f"{LISTING_URL}{i}/")
    return urls

def extract_cves(text):
    return re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)

def scrape_vm_details(link):
    vm_data = {}
    try:
        response = requests.get(link)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        vm_data["title"] = soup.find("h1").get_text(strip=True)
        vm_data["url"] = link

        # Extract description text
        description_tag = soup.find("div", class_="description")
        if description_tag:
            description = description_tag.get_text(" ", strip=True)
            vm_data["description"] = description
            vm_data["cves"] = extract_cves(description)
        else:
            vm_data["description"] = ""
            vm_data["cves"] = []

    except Exception as e:
        print(f"Error scraping {link}: {e}")
    return vm_data

def scrape_vulnhub(max_pages=5):
    all_vms = []
    listing_urls = get_listing_pages(max_pages)
    for page_url in listing_urls:
        print(f"🔄 Scraping: {page_url}")
        response = requests.get(page_url)
        soup = BeautifulSoup(response.text, "html.parser")
        links = soup.select(".vm-title > a")
        for link in links:
            full_url = BASE_URL + link.get("href")
            vm_info = scrape_vm_details(full_url)
            all_vms.append(vm_info)
    return all_vms

def main():
    os.makedirs("data", exist_ok=True)
    vms = scrape_vulnhub(max_pages=3)  # You can adjust number of pages
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(vms, f, indent=2)
    print(f"✅ VulnHub VM metadata saved to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
