import subprocess

# Define all the scripts in your pipeline
scripts = [
    "scripts/github_poc_integrator.py",
    "scripts/scrape_vulnhub.py",
    "scripts/scrape_packetstorm.py",
    "scripts/generate_master_dataset.py",
    "scripts/json_to_sqlite.py",
    "scripts/convert_jsonl_to_csv.py"
]

# Execute each script with error and timeout handling
for script in scripts:
    print(f"\n🔄 Running {script}...")
    try:
        result = subprocess.run(["python", script], timeout=600)  # 10 min timeout
        if result.returncode != 0:
            print(f"❌ Error: {script} exited with code {result.returncode}. Stopping pipeline.")
            break
        print(f"✅ Finished {script}")
    except subprocess.TimeoutExpired:
        print(f"⏱️ Timeout: {script} took too long and was skipped.")
        break
    except Exception as e:
        print(f"❌ Unexpected error while running {script}: {e}")
        break

print("\n🏁 Pipeline completed.")
