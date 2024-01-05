# vrt-to-cwe

A script for converting bug bounty reports from the [Vulnerability Rating Taxonomy (VRT)](https://github.com/bugcrowd/vulnerability-rating-taxonomy) to [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/) using the mapping maintained [here](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/mappings/cwe/cwe.json).

This script will take weaknesses in [exported data](https://docs.bugcrowd.com/customers/the-insights-dashboard/download-reports-and-export-submission-data/#exporting-submission-data-to-csv) and prepare it in [a format ready to be imported](https://docs.hackerone.com/en/articles/8541742-import-vulnerabilities).
