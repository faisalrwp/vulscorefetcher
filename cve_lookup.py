# cve_lookup.py
# Advanced CVE lookup module with full SQLite caching, expiry, NVD key management,
# EPSS API integration, detailed tables, force-update, and rate limiting.

import sqlite3
import requests
import time
import base64
import os
import json
from datetime import datetime, timedelta
# from dateutil import parser

# ---------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------
DB_FILE = "cve_cache.db"
NVD_KEY_FILE = "nvd.key"
CACHE_EXPIRY_DAYS = 15

EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RATE_LIMIT_SLEEP = 1.6   # 1 request per 1.6 sec to avoid NVD rate block


# ---------------------------------------------------------
# LOG HELPER (GUI SAFE)
# ---------------------------------------------------------
def log(msg, callback=None):
    if callback:
        callback(msg)
    else:
        print(msg)


# ---------------------------------------------------------
# SQLITE INITIALIZATION
# ---------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Table 1: EPSS Cache
    cur.execute("""
        CREATE TABLE IF NOT EXISTS epss_cache (
            cve_id TEXT PRIMARY KEY,
            epss REAL,
            last_updated TEXT
        )
    """)

    # Table 2: CVSS Cache
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cvss_cache (
            cve_id TEXT PRIMARY KEY,
            cvss REAL,
            vector TEXT,
            last_updated TEXT
        )
    """)

    # Table 3: EPSS Detail
    cur.execute("""
        CREATE TABLE IF NOT EXISTS epss_detail (
            cve_id TEXT PRIMARY KEY,
            detail_json TEXT,
            last_updated TEXT
        )
    """)

    # Table 4: CVE Detail
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cve_detail (
            cve_id TEXT PRIMARY KEY,
            detail_json TEXT,
            last_updated TEXT
        )
    """)

    # Indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_epss_cve ON epss_cache(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cvss_cve ON cvss_cache(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_epss_det_cve ON epss_detail(cve_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_cve_det_cve ON cve_detail(cve_id)")

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# NVD KEY MANAGEMENT
# ---------------------------------------------------------
def check_nvd_api_key():
    """Returns True if an encoded NVD API key exists."""
    return os.path.exists(NVD_KEY_FILE)


def get_nvd_api_key():
    if not os.path.exists(NVD_KEY_FILE):
        return None
    try:
        with open(NVD_KEY_FILE, "rb") as f:
            encoded = f.read().strip()
            return base64.b64decode(encoded).decode("utf-8")
    except:
        return None


def prompt_and_store_nvd_key():
    key = input("Enter your NVD API Key: ").strip()
    if not key:
        return None

    encoded = base64.b64encode(key.encode("utf-8"))
    with open(NVD_KEY_FILE, "wb") as f:
        f.write(encoded)

    return key


# ---------------------------------------------------------
# CACHE CHECKER
# ---------------------------------------------------------
def is_cache_valid(date_str):
    # """Returns True if cache < 15 days."""
    # try:
    #     dt = parser.parse(date_str)
    #     return (datetime.now() - dt) < timedelta(days=CACHE_EXPIRY_DAYS)
    # except:
    #     return False
    try:
        dt = datetime.fromisoformat(date_str)
        # Return True when cache is still valid (i.e. age < expiry)
        return (datetime.now() - dt) < timedelta(days=CACHE_EXPIRY_DAYS)
    except Exception:
        return False


# ---------------------------------------------------------
# API CALLERS
# ---------------------------------------------------------
def fetch_epss(cve_id):
    """Call EPSS API."""
    try:
        r = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=10)
        data = r.json()

        if "data" not in data or len(data["data"]) == 0:
            return None, None

        entry = data["data"][0]
        try:
            return float(entry.get("epss", 0.0)), data
        except Exception:
            return None, data
    except Exception:
        return None, None


def fetch_cvss(cve_id, api_key):
    """Call NVD CVE API."""
    try:
        time.sleep(RATE_LIMIT_SLEEP)  # avoid rate block

        headers = {"apiKey": api_key} if api_key else {}

        r = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=10)
        data = r.json()

        if "vulnerabilities" not in data or len(data["vulnerabilities"]) == 0:
            return None, None, None

        vuln = data["vulnerabilities"][0]["cve"]

        metrics = vuln.get("metrics", {})
        cvss = None
        vector = None

        # CVSS V3.1
        if "cvssMetricV31" in metrics:
            m = metrics["cvssMetricV31"][0]
            cvss = m["cvssData"]["baseScore"]
            vector = m["cvssData"]["vectorString"]

        # CVSS V3.0
        elif "cvssMetricV30" in metrics:
            m = metrics["cvssMetricV30"][0]
            cvss = m["cvssData"]["baseScore"]
            vector = m["cvssData"]["vectorString"]

        # CVSS V2 fallback
        elif "cvssMetricV2" in metrics:
            m = metrics["cvssMetricV2"][0]
            cvss = m["cvssData"]["baseScore"]
            vector = m["cvssData"]["vectorString"]

        return cvss, vector, data

    except:
        return None, None, None


# ---------------------------------------------------------
# LOOKUP MASTER FUNCTION
# ---------------------------------------------------------
def lookup_cve(cve_id, full=False, log_callback=None):
    """
    Returns (epss, cvss) or full detail (if full=True).
    Automatically handles cache, expiry, + API fallback.
    """
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # -----------------------------------------------------
    # 1. Check EPSS cache
    # -----------------------------------------------------
    cur.execute("SELECT epss, last_updated FROM epss_cache WHERE cve_id=?", (cve_id,))
    row = cur.fetchone()
    epss = None
    epss_raw = None

    if row:
        epss_score, last_updated = row
        if is_cache_valid(last_updated):
            epss = epss_score
            log(f"[CACHE] EPSS hit for {cve_id}", log_callback)
        else:
            log(f"[CACHE] EPSS expired for {cve_id}", log_callback)
    else:
        log(f"[CACHE] No EPSS entry for {cve_id}", log_callback)

    # -----------------------------------------------------
    # Fetch EPSS if not in cache or expired
    # -----------------------------------------------------
    if epss is None:
        epss, epss_raw = fetch_epss(cve_id)

        if epss is not None:
            cur.execute(
                "REPLACE INTO epss_cache (cve_id, epss, last_updated) VALUES (?, ?, ?)",
                (cve_id, epss, datetime.now().isoformat())
            )

            if epss_raw:
                cur.execute(
                    "REPLACE INTO epss_detail (cve_id, detail_json, last_updated) VALUES (?, ?, ?)",
                    (cve_id, str(epss_raw), datetime.now().isoformat())
                )

            conn.commit()

    # -----------------------------------------------------
    # 2. CVSS Cache Check
    # -----------------------------------------------------
    cur.execute("SELECT cvss, vector, last_updated FROM cvss_cache WHERE cve_id=?", (cve_id,))
    row = cur.fetchone()
    cvss = None
    vector = None
    cvss_raw = None

    if row:
        cvss_score, vec, last_updated = row
        if is_cache_valid(last_updated):
            cvss = cvss_score
            vector = vec
            log(f"[CACHE] CVSS hit for {cve_id}", log_callback)
        else:
            log(f"[CACHE] CVSS expired for {cve_id}", log_callback)
    else:
        log(f"[CACHE] No CVSS entry for {cve_id}", log_callback)

    # -----------------------------------------------------
    # Fetch CVSS if needed
    # -----------------------------------------------------
    if cvss is None:
        api_key = get_nvd_api_key()

        if not api_key:
            log("[NVD] Missing API Key. Cannot fetch CVSS.", log_callback)
        else:
            cvss, vector, cvss_raw = fetch_cvss(cve_id, api_key)

            if cvss is not None:
                cur.execute(
                    "REPLACE INTO cvss_cache (cve_id, cvss, vector, last_updated) VALUES (?, ?, ?, ?)",
                    (cve_id, cvss, vector, datetime.now().isoformat())
                )

                if cvss_raw:
                    cur.execute(
                        "REPLACE INTO cve_detail (cve_id, detail_json, last_updated) VALUES (?, ?, ?)",
                        (cve_id, str(cvss_raw), datetime.now().isoformat())
                    )

                conn.commit()

    conn.close()

    # -----------------------------------------------------
    # Return results (simple or full)
    # -----------------------------------------------------
    if full:
        return {
            "cve": cve_id,
            "epss": epss,
            "cvss": cvss,
            "vector": vector,
            "epss_detail": epss_raw,
            "cvss_detail": cvss_raw
        }

    return epss, cvss


# ---------------------------------------------------------
# UPDATE DATABASE (Global Refresh)
# ---------------------------------------------------------
def update_db(force=False, log_callback=None):
    """
    Loops over all cache entries and refreshes if expired or force=True.
    """
    log("[DB] Starting update...", log_callback)

    init_db()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Get all CVEs in cache
    cur.execute("SELECT cve_id, last_updated FROM cvss_cache")
    rows = cur.fetchall()

    for cve_id, last_updated in rows:
        if force or not is_cache_valid(last_updated):
            log(f"[DB] Updating {cve_id}", log_callback)
            lookup_cve(cve_id, full=True, log_callback=log_callback)
        else:
            log(f"[DB] Skipping fresh {cve_id}", log_callback)

    conn.close()
    log("[DB] Update complete.", log_callback)


# ---------------------------------------------------------
# SELF TEST
# ---------------------------------------------------------
if __name__ == "__main__":
    print("Standalone test mode.")
    c = input("Enter CVE ID: ").strip().upper()
    update_db(force=True)
    if (c == "UPDATE"):
        update_db(force=False)
    elif (c == "FUPATE"):
        update_db(force=True)
    else:
        print(lookup_cve(c, full=True))
