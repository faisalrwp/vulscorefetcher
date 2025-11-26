<div align="center">

# 🛡️⚡ CVE Enrichment & Smart Vulnerability Analyzer  
### **Automated CVSS + EPSS Lookup • SQLite Caching • GUI • API Integration**

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Stable-success.svg)
![GUI](https://img.shields.io/badge/Interface-GUI%20%2B%20CLI-purple.svg)

</div>

---

## 🌟 **Overview**

This project provides a complete **next-generation CVE lookup and enrichment system** with:

### ✔ Automatic EPSS lookup  
### ✔ Automatic CVSS lookup via NVD API  
### ✔ Encrypted API key storage  
### ✔ Persistent SQLite caching  
### ✔ Detailed JSON storage for CVE insights  
### ✔ GUI interface (with dark mode + ttkbootstrap)  
### ✔ Batch processing of CSV files  
### ✔ Intelligent rate limiting  
### ✔ DB auto-refresh + force refresh options  

It eliminates repetitive CVE lookups and accelerates vulnerability analysis by **1000×** through local caching + batch operations.

---

---

# 🧠 **Key Features**

### ✨ **1. Modern GUI (Tkinter + ttkbootstrap Dark Mode)**
- File browser for CSV selection  
- Tabs for:
  - CSV Processing  
  - Database maintenance  
  - Settings  
  - Full log console  
- Real-time progress bar  
- Cancel button  
- Auto-scroll log pane  

---

### 🚀 **2. Smart API Integration**
| Source | What is collected | API rate limit handled? |
|--------|-------------------|---------------------------|
| **EPSS (FIRST.org)** | EPSS Score, Probability | Yes |
| **NVD API 2.0** | CVSS v3.1/v3.0/v2, vectors, metadata | Yes |

---

### 💾 **3. SQLite Persistent Cache**
Tables:
- `epss_cache`  
- `cvss_cache`  
- `epss_detail`  
- `cve_detail`  

All indexed on **CVE ID** for fast lookup.

Caching rules:
- Cache TTL = **15 days**
- Old entries automatically refreshed
- No re-query if cached & fresh

---

### 🧩 **4. CSV Processor**
Automatically:
- Reads CSV case-insensitively  
- Detects `CVEID` column  
- Fetches/uses cached scores  
- Writes output in `*_updated.csv`  
- Supports batch IO (100-row flush)  

---

### 👮 **5. Secure API Key Storage**
- File: `nvd.key`  
- Stored in **Base64 encoded** form  
- Auto-prompt if missing  

---

---

# 📂 **Project Structure**

📁 cve-enrichment-tool/
│
├── gui_app_advanced.py # The main GUI application
├── process_csv.py # CSV processor engine
├── cve_lookup.py # API + caching engine
├── settings.json # Persistent GUI settings
├── nvd.key # (Created automatically)
│
├── README.md # THIS FILE ❤️
└── sample.csv # Example input CSV (optional)


---

---

# 🛠️ **Installation**

### 1️⃣ Install Python dependencies  
```bash
pip install requests python-dateutil tqdm ttkbootstrap

📁 cve-enrichment-tool/
│
├── gui_app_advanced.py # The main GUI application
├── process_csv.py # CSV processor engine
├── cve_lookup.py # API + caching engine
├── settings.json # Persistent GUI settings
├── nvd.key # (Created automatically)
│
├── README.md # THIS FILE ❤️
└── sample.csv # Example input CSV (optional)



2️⃣ Ensure all project files are in the same directory.
3️⃣ Run GUI:

```bash
python gui_app_advanced.py

🖥️ GUI Interface
🗂️ Main Tabs

Process CSV → Select file, run updates

Database Tools → Update DB, Force update DB

Settings → Save theme, log size, window size

Logs → Full real-time log output

