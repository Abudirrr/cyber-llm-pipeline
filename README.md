# 🔐 Cyber LLM Vulnerability Pipeline

A fully automated vulnerability enrichment pipeline that pulls, merges, and processes CVE data from multiple trusted sources — daily.

---

## 📦 Dataset Features

The pipeline produces a master dataset (`master_dataset.jsonl`) with up-to-date and enriched vulnerability records from:

| Source          | Data Included |
|-----------------|----------------|
| **NVD**         | CVE ID, severity, description, CVSS scores, affected products |
| **CISA KEV**    | Exploited flag, vendor mitigations, criticality |
| **Exploit-DB**  | Public exploit links, platforms, types |
| **GitHub PoCs** | Live Proof-of-Concept repositories, authors, dates |
| **PacketStorm** | Exploit metadata from security community |
| **VulnHub**     | Realistic vulnerable environments (VMs) |
| **CSV Flags**   | High severity / unpatched indicators, GitHub PoC presence |

---

## 🧠 Target Use Cases

- LLM training for cybersecurity
- Threat intelligence enrichment
- Vulnerability scoring/classification
- Exploit prediction and patch triage

---

## 📁 Files

| File | Description |
|------|-------------|
| `data/master_dataset.jsonl` | 🔥 Final LLM-ready JSON Lines dataset |
| `data/merged_vulnerabilities.json` | Merged NVD + CISA + Exploit-DB |
| `data/merged_vulnerabilities_with_github_poc.json` | + GitHub PoC links |
| `data/github_pocs.json` | Cached GitHub PoC entries |
| `data/nvd_2024.json.gz` | Original NVD feed |
| `scripts/` | All enrichment and scraper scripts |
| `.github/workflows/pipeline.yml` | GitHub Actions automation (runs daily) |

---

## 🔄 Automation

This repo runs **daily at 03:00 UTC** using GitHub Actions to:
- Fetch the latest NVD, CISA KEV, Exploit-DB data
- Scrape PacketStorm, GitHub, and VulnHub
- Merge all data into a structured `master_dataset.jsonl`
- Commit changes back to the repository

---

## 📥 Usage

Clone the repo:

```bash
git clone https://github.com/Abudirrr/cyber-llm-pipeline.git
cd cyber-llm-pipeline
