import requests
from bs4 import BeautifulSoup
import json
import re
import os

BASE_URL = "https://packetstormsecurity.com"
LISTING_URL = f"{BASE_URL}/files/"
OUTPUT_PATH = "data/packetstorm_exploits.json"

def extract_cves(text):
    return re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)

def scrape_listing_page(url):
    exploits = []
    print(f"🔄 Scraping: {url}")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    rows = soup.select(".file")
    for row in rows:
        title_tag = row.select_one(".title")
        if not title_tag:
            continue
        link = BASE_URL + title_tag.get("href", "")
        title = title_tag.get_text(strip=True)
        date_tag = row.select_one(".date")
        date = date_tag.get_text(strip=True) if date_tag else ""
        tags = [tag.get_text(strip=True) for tag in row.select(".tags a")]
        cves = extract_cves(title)

        exploits.append({
            "title": title,
            "url": link,
            "date": date,
            "tags": tags,
            "cves": cves
        })
    return exploits

def scrape_packetstorm(pages=3):
    all_exploits = []
    for i in range(pages):
        suffix = "" if i == 0 else f"page{i + 1}.shtml"
        page_url = f"{LISTING_URL}{suffix}"
        exploits = scrape_listing_page(page_url)
        all_exploits.extend(exploits)
    return all_exploits

def main():
    os.makedirs("data", exist_ok=True)
    exploits = scrape_packetstorm(pages=3)  # Adjust number of pages as needed
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(exploits, f, indent=2)
    print(f"✅ PacketStorm exploits saved to {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
