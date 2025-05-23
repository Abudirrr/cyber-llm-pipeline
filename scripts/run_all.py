import subprocess

scripts = [
    "scripts/github_poc_integrator.py",
    "scripts/scrape_vulnhub.py",
    "scripts/scrape_packetstorm.py",
    "scripts/json_to_sqlite.py"
]

for script in scripts:
    print(f"Running {script}...")
    subprocess.run(["python", script])
