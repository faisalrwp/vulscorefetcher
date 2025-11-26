# process_csv.py
# Enhanced CSV processor with GUI callbacks, batch writing, fast caching, and safe cancellation.

import csv
import os
from tqdm import tqdm
from cve_lookup import lookup_cve
from typing import Callable, Optional


# ---------------------------------------------------------
# Helper: Find file case-insensitively
# ---------------------------------------------------------
def find_file_case_insensitive(filename: str) -> Optional[str]:
    """
    Search for a file regardless of upper/lower case.
    """
    directory = os.getcwd()
    target = filename.lower()

    for f in os.listdir(directory):
        if f.lower() == target:
            return f

    return None


# ---------------------------------------------------------
# Helper: Detect CVE column name (case-insensitive)
# ---------------------------------------------------------
def find_cve_column(fieldnames):
    for name in fieldnames:
        if name.lower() == "cveid":
            return name
    return None


# ---------------------------------------------------------
# Main CSV Processing Function
# ---------------------------------------------------------
def process_and_update_csv(
    csv_file_path: str,
    progress_callback: Callable[[int, int], None] = None,
    log_callback: Callable[[str], None] = None,
    cancel_check: Callable[[], bool] = None
):
    """
    Processes CSV by adding EPSS and CVSS columns.
    Supports progress callbacks and cancellation for GUI use.
    """

    def log(msg):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)

    # ---------------------------------------------
    # Step 1: Locate file case-insensitively
    # ---------------------------------------------
    actual_file = find_file_case_insensitive(csv_file_path)
    if not actual_file:
        raise FileNotFoundError(
            f"File '{csv_file_path}' could not be found (case-insensitive search)."
        )

    log(f"[PROCESS] Located file: {actual_file}")

    # ---------------------------------------------
    # Step 2: Load CSV rows into memory buffer
    # ---------------------------------------------
    try:
        with open(actual_file, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

            if not rows:
                raise ValueError("CSV file is empty.")

            fieldnames = reader.fieldnames

    except Exception as e:
        raise RuntimeError(f"Failed to open CSV: {e}")

    # ---------------------------------------------
    # Step 3: Identify CVEID column
    # ---------------------------------------------
    cve_column = find_cve_column(fieldnames)
    if not cve_column:
        raise KeyError("No CVEID column found in CSV (case-insensitive search failed).")

    log(f"[PROCESS] CVE column detected: {cve_column}")

    # Prepare output
    base, ext = os.path.splitext(actual_file)
    output_file = f"{base}_updated{ext}"

    new_fields = fieldnames + ["epss", "cvss"]

    # ---------------------------------------------
    # Step 4: Process with fast batch writing
    # ---------------------------------------------
    total_rows = len(rows)
    processed = 0

    batch_buffer = []
    batch_size = 100  # fast, low disk I/O

    log("[PROCESS] Starting per-row CVE lookups...")

    try:
        with open(output_file, "w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=new_fields)
            writer.writeheader()

            # ---------------------------------------------
            # Loop over rows
            # ---------------------------------------------
            for row in rows:
                # Cancel if requested
                if cancel_check and cancel_check():
                    log("[PROCESS] Cancel requested by user.")
                    return

                cve_value = row.get(cve_column)

                if not cve_value or cve_value.strip() == "":
                    row["epss"] = "Missing"
                    row["cvss"] = "Missing"
                else:
                    try:
                        epss, cvss = lookup_cve(cve_value)
                        row["epss"] = epss if epss else "Not Found"
                        row["cvss"] = cvss if cvss else "Not Found"
                    except Exception as e:
                        row["epss"] = "Error"
                        row["cvss"] = "Error"
                        log(f"[ERROR] Failed lookup for {cve_value}: {e}")

                batch_buffer.append(row)
                processed += 1

                # flush batch
                if len(batch_buffer) >= batch_size:
                    writer.writerows(batch_buffer)
                    batch_buffer.clear()

                # update progress
                if progress_callback:
                    progress_callback(processed, total_rows)

            # flush final rows
            if batch_buffer:
                writer.writerows(batch_buffer)

    except Exception as e:
        raise IOError(f"Failed while writing updated CSV: {e}")

    log(f"[PROCESS] Finished processing. Output saved as {output_file}")
    return output_file



# ---------------------------------------------------------
# CLI TESTING MODE
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Standalone test mode.")
    filename = input("Enter CSV file name: ").strip()

    def p(i, t):
        print(f"Progress: {i}/{t}")

    def lg(msg):
        print(msg)

    process_and_update_csv(
        filename,
        progress_callback=p,
        log_callback=lg,
        cancel_check=lambda: False
    )
