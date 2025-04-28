#!/usr/bin/env python3
"""Convert Bugcrowd VRT categories to human-readable CWE names."""
__version__ = "0.1.0"
import csv
import json
import io
import zipfile
import xml.etree.ElementTree as ET
import requests
import argparse
import logging
import sys


# Load CWE ID to string mapping from a CSV file provided by MITRE
def load_cwe_mapping(file_path):
    cwe_names = {}
    with open(file_path, mode="r") as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            # Adjust the CWE-ID to match the format in the VRT mapping (e.g., "79" instead of "CWE-79")
            cwe_id = "CWE-" + row["CWE-ID"]
            cwe_name = row["Name"]
            cwe_names[cwe_id] = cwe_name
    return cwe_names


# Fetch the the latest VRT to CWE mapping from GitHub
def fetch_mapping(url):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        json_data = response.json()
        # Get default CWE mapping (for unmapped categories) if provided
        meta = json_data.get("metadata", {}) or {}
        default_cwe = meta.get("default")
        # Normalize default to a list
        if default_cwe is None:
            default_cwe = []
        # Flatten the content mapping, inheriting default_cwe at the root
        content = json_data.get("content", []) or []
        mapping = flatten_mapping(content, inherited_cwe=default_cwe)
        # Store default mapping under empty key for fallback
        mapping[""] = default_cwe
        return mapping
    except requests.RequestException as e:
        logging.error(f"Error fetching mapping: {e}")
        sys.exit(1)


def load_deprecated_map(url):
    """
    Fetch and process the deprecated-node-mapping.json, returning a map
    of old VRT IDs to their latest new VRT ID.
    """
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        logging.warning(f"Could not fetch deprecated mapping: {e}")
        return {}
    deprecated = {}
    for old_id, versions in data.items():
        if not isinstance(versions, dict):
            continue
        best_ver = None
        best_new = None
        for ver_str, new_id in versions.items():
            # parse version like '1.2' into tuple of ints
            parts = tuple()
            try:
                parts = tuple(int(p) for p in ver_str.split(".") if p.isdigit())
            except ValueError:
                continue
            if best_ver is None or parts > best_ver:
                best_ver, best_new = parts, new_id
        if best_new:
            deprecated[old_id] = best_new
    return deprecated


# Fetch comprehensive CWE ID to name mapping by downloading MITRE’s XML catalog
def fetch_cwe_names(url="https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"):
    """
    Downloads and parses the CWE catalog XML to build a mapping of CWE-ID to CWE name.
    """
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        # Unzip and read XML file
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        xml_filename = next(name for name in zf.namelist() if name.endswith(".xml"))
        xml_data = zf.read(xml_filename)
        # Parse XML
        root = ET.fromstring(xml_data)
        ns = "{http://cwe.mitre.org/cwe-7}"
        cwe_names = {}
        # Collect names from both Weakness and Category elements
        for tag in ("Weakness", "Category"):
            for elem in root.findall(f".//{ns}{tag}"):
                cid = elem.get("ID")
                name = elem.get("Name")
                if cid and name:
                    cwe_names[f"CWE-{cid}"] = name
        return cwe_names
    except Exception as e:
        logging.error(f"Error fetching CWE names: {e}")
        sys.exit(1)


# Flattens the hierarchical mapping to a simple dictionary
def flatten_mapping(mapping, parent_id=None, inherited_cwe=None):
    """
    Recursively flatten the hierarchical VRT->CWE mapping.
    If an item has no explicit CWE (None), inherit from parent (or default).
    """
    flat_map = {}
    for item in mapping:
        vrt_id = item.get("id")
        combined_id = f"{parent_id}.{vrt_id}" if parent_id else vrt_id
        # Determine CWE list: use explicit list or inherit if None
        raw = item.get("cwe")
        if raw is None:
            cwe_list = inherited_cwe or []
        else:
            cwe_list = raw
        flat_map[combined_id] = cwe_list
        # Recurse into children, passing down the inherited CWE list
        children = item.get("children") or []
        if children:
            flat_map.update(flatten_mapping(children, combined_id, cwe_list))
    return flat_map


# Maps a VRT category to a CWE, considering hierarchical structure
def map_vrt_to_cwe(vrt, mapping):
    """
    Map a VRT category (possibly hierarchical, dot-separated) to its CWE list.
    Attempts the full category, then progressively strips subcategories.
    Falls back to default mapping if provided (empty key), else empty list.
    """
    parts = vrt.split(".") if isinstance(vrt, str) else []
    # Try most specific to least specific category
    for i in range(len(parts), 0, -1):
        sub = ".".join(parts[:i])
        if sub in mapping:
            return mapping[sub] or []
    # Fallback to default if available
    return mapping.get("", []) or []


# Converts VRT categories in a CSV file to CWEs and writes to a new file
def convert_vrt_to_cwe(
    input_csv, output_csv, vrt_column, mapping, cwe_names, deprecated_map=None
):
    try:
        with open(input_csv, mode="r") as infile, open(
            output_csv, mode="w", newline=""
        ) as outfile:
            reader = csv.DictReader(infile)
            if reader.fieldnames is None:
                logging.error("CSV file is missing a header row.")
                sys.exit(1)

            fieldnames = list(reader.fieldnames) + ["CWE"]
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)

            writer.writeheader()
            for row in reader:
                # Handle deprecated VRT IDs
                vrt_category = row.get(vrt_column, "")
                if deprecated_map:
                    # Update deprecated IDs until up-to-date
                    while vrt_category in deprecated_map:
                        new_cat = deprecated_map[vrt_category]
                        logging.debug(
                            "Deprecated VRT ID '%s' replaced by '%s'",
                            vrt_category,
                            new_cat,
                        )
                        vrt_category = new_cat
                cwe_ids = map_vrt_to_cwe(vrt_category, mapping)
                # Only use the first CWE ID and map it to a CWE name (fall back to ID if name missing)
                first_cwe_id = cwe_ids[0] if cwe_ids else None
                if first_cwe_id:
                    name = cwe_names.get(first_cwe_id)
                    # use name if available, otherwise use the CWE ID itself
                    row["CWE"] = name if name else first_cwe_id
                else:
                    row["CWE"] = ""
                writer.writerow(row)

        logging.info("Conversion completed. Output saved to %s", output_csv)
    except Exception as e:
        logging.error(f"Error processing CSV file: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Convert Bugcrowd VRT categories in a CSV file to human-readable CWE names.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "-m",
        "--mapping-url",
        default="https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/mappings/cwe/cwe.json",
        help="URL for VRT→CWE mapping JSON.",
    )
    parser.add_argument(
        "-d",
        "--deprecated-url",
        default="https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/deprecated-node-mapping.json",
        help="URL for deprecated-node mapping JSON.",
    )
    parser.add_argument(
        "-l",
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level.",
    )
    parser.add_argument(
        "input_csv", help="Path to the input CSV file containing VRT categories."
    )
    parser.add_argument(
        "output_csv", help="Path to the output CSV file where the result will be saved."
    )
    parser.add_argument(
        "vrt_column",
        help="The column name in the CSV file that contains the VRT categories.",
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=args.log_level, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Load CWE names mapping from MITRE XML catalog
    cwe_names = fetch_cwe_names()

    # Fetch and flatten VRT to CWE mapping and deprecated-node mapping from GitHub
    vrt_to_cwe_mapping = fetch_mapping(args.mapping_url)
    deprecated_map = load_deprecated_map(args.deprecated_url)

    # Perform conversion (applying deprecated ID remapping)
    convert_vrt_to_cwe(
        args.input_csv,
        args.output_csv,
        args.vrt_column,
        vrt_to_cwe_mapping,
        cwe_names,
        deprecated_map,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
