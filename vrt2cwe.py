import csv
import requests
import argparse
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load CWE ID to string mapping from a CSV file provided by MITRE
def load_cwe_mapping(file_path):
    cwe_names = {}
    with open(file_path, mode='r') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            # Adjust the CWE-ID to match the format in the VRT mapping (e.g., "79" instead of "CWE-79")
            cwe_id = 'CWE-' + row['CWE-ID']
            cwe_name = row['Name']
            cwe_names[cwe_id] = cwe_name
    return cwe_names

# Fetch the the latest VRT to CWE mapping from GitHub
def fetch_mapping(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_data = response.json()
        # Here we access the 'content' key which contains the list of VRT mappings
        return flatten_mapping(json_data['content'])
    except requests.RequestException as e:
        logging.error(f"Error fetching mapping: {e}")
        sys.exit(1)

# Flattens the hierarchical mapping to a simple dictionary
def flatten_mapping(mapping, parent_id=None, inherited_cwe=None):
    flat_map = {}
    for item in mapping:
        vrt_id = item['id']
        combined_id = f"{parent_id}.{vrt_id}" if parent_id else vrt_id
        cwe_list = item.get('cwe', inherited_cwe or [])  # Inherit CWE if not present
        flat_map[combined_id] = cwe_list
        if 'children' in item:
            flat_map.update(flatten_mapping(item['children'], combined_id, cwe_list))
    return flat_map

# Maps a VRT category to a CWE, considering hierarchical structure
def map_vrt_to_cwe(vrt, mapping):
    parts = vrt.split('.')
    for i in range(len(parts), 0, -1):
        subcategory = '.'.join(parts[:i])
        if subcategory in mapping:
            return mapping[subcategory]
    return []  # Return an empty list if no CWE is found

# Converts VRT categories in a CSV file to CWEs and writes to a new file
def convert_vrt_to_cwe(input_csv, output_csv, vrt_column, mapping, cwe_names):
    try:
        with open(input_csv, mode='r') as infile, open(output_csv, mode='w', newline='') as outfile:
            reader = csv.DictReader(infile)
            if reader.fieldnames is None:
                logging.error("CSV file is missing a header row.")
                sys.exit(1)

            fieldnames = list(reader.fieldnames) + ['CWE']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)

            writer.writeheader()
            for row in reader:
                vrt_category = row[vrt_column]
                cwe_ids = map_vrt_to_cwe(vrt_category, mapping)
                # Only use the first CWE ID and map it to a CWE name
                first_cwe_id = cwe_ids[0] if cwe_ids else None
                cwe_name = cwe_names.get(first_cwe_id, '') if first_cwe_id else ''
                row['CWE'] = cwe_name
                writer.writerow(row)

        logging.info("Conversion completed. Output saved to %s", output_csv)
    except Exception as e:
        logging.error(f"Error processing CSV file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Script that converts VRT categories in a CSV file to CWEs, fetching the latest mapping from GitHub."
    )
    parser.add_argument("input_csv", help="Path to the input CSV file containing VRT categories.")
    parser.add_argument("output_csv", help="Path to the output CSV file where the result will be saved.")
    parser.add_argument("vrt_column_name", help="The column name in the CSV file that contains the VRT categories.")
    args = parser.parse_args()

    # Load CWE names mapping
    cwe_mapping_file = 'all-cwes.csv'  # Replace with your actual file path
    cwe_names = load_cwe_mapping(cwe_mapping_file)

    # Fetch and flatten VRT to CWE mapping from GitHub
    mapping_url = 'https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/mappings/cwe/cwe.json'
    vrt_to_cwe_mapping = fetch_mapping(mapping_url)

    # Perform conversion
    convert_vrt_to_cwe(args.input_csv, args.output_csv, args.vrt_column_name, vrt_to_cwe_mapping, cwe_names)

if __name__ == "__main__":
    main()