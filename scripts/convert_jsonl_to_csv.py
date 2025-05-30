import json
import pandas as pd

def convert_jsonl_to_csv(jsonl_path, csv_path):
    # Read each line as a JSON object
    with open(jsonl_path, 'r', encoding='utf-8') as file:
        data = [json.loads(line) for line in file]

    # Convert to DataFrame and save as CSV
    df = pd.DataFrame(data)
    df.to_csv(csv_path, index=False)
    print(f"Converted '{jsonl_path}' to '{csv_path}'")

# Example usage
if __name__ == "__main__":
    convert_jsonl_to_csv(
        jsonl_path="data/master_dataset.jsonl",
        csv_path="data/master_dataset.csv"
    )
