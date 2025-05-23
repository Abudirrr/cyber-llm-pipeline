import sqlite3
import pandas as pd

# Connect to your database
conn = sqlite3.connect("vulnerabilities.db")

# Define your query
query = """
SELECT id, severity, patch_available, description
FROM vulns
WHERE severity = 'HIGH' AND patch_available = 0
LIMIT 100;
"""

# Execute query
df = pd.read_sql_query(query, conn)

# Save to CSV
df.to_csv("high_unpatched.csv", index=False)
print("✅ Query complete. Results saved to 'high_unpatched.csv'")
