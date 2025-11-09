# timeline_builder.py — Summary

- What it does: Reads CSV log files (email, web, WAF, API) from the `materials` folder and detects events such as phishing, SQL injection attempts, WAF alerts, broken access control (IDOR), brute-force attempts, and account enumeration. It builds a timeline and an IOC list from detected events.
- Results: Generates `analysis_output/timeline.csv` and `analysis_output/iocs.csv` and prints summary statistics (event counts, severity distribution) to the console.
- Notes: Handles file permission issues by writing an alternative filename if the target CSV is open.
