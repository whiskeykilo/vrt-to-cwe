# vrt2cwe

A script to  convert [Vulnerability Rating Taxonomy (VRT)](https://github.com/bugcrowd/vulnerability-rating-taxonomy) categories to human-readable [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) names.

## Overview

This script reads an input CSV containing one column of VRT category identifiers (e.g., "cross_site_scripting_xss.stored.url_based"), fetches the latest VRT→CWE mapping and any deprecated-node updates from Bugcrowd’s VRT repository on GitHub, and downloads the latest CWE catalog from MITRE to resolve CWE IDs to names. The output CSV includes all original columns plus a new `CWE` column with a string of the first mapped CWE name (or blank if none).

### Use Case

This script will take weaknesses in [exported bug bounty data](https://docs.bugcrowd.com/customers/the-insights-dashboard/download-reports-and-export-submission-data/#exporting-submission-data-to-csv) and prepare it in [a format ready to be imported](https://docs.hackerone.com/en/articles/8541742-import-vulnerabilities).

## Features

- Automatically fetches the latest [VRT→CWE mapping](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/mappings/cwe/cwe.json) and deprecated-node mapping from Bugcrowd’s VRT repository on GitHub
- Downloads the latest CWE catalog from MITRE's website to map CWE IDs to names
- Handles hierarchical VRT categories and falls back to parent or default mappings
- Appends a `CWE` column with the first CWE name per vulnerability

## Requirements

- Python 3.7+
- requests

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python vrt2cwe.py <input_csv> <output_csv> <vrt_column>
```

Arguments:

- `<input_csv>`: Path to the input CSV file containing VRT categories.
- `<output_csv>`: Path where the converted CSV with CWE names will be saved.
- `<vrt_column>`: Name of the column in the input CSV holding the VRT category identifiers.

Example:

```bash
python vrt2cwe.py test_input_file.csv out.csv weakness_name
```

### Output

The script writes `<output_csv>` with all original fields plus a new `CWE` column containing the first mapped CWE name (or blank if no mapping).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
