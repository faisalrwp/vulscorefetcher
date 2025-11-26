# gui_app_advanced.py
# Multi-tab advanced dark GUI for CVE CSV processing
# Uses ttkbootstrap for modern UI

import os
import json
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import sqlite3
from datetime import datetime

from cve_process import process_and_update_csv
from cve_lookup import update_db, check_nvd_api_key, prompt_and_store_nvd_key


SETTINGS_FILE = "settings.json"


# ---------------------------------------------------------
# Settings Persistence
# ---------------------------------------------------------
def load_settings():
    if not os.path.exists(SETTINGS_FILE):
        return {
            "last_csv": "",
            "update_db": False,
            "force_update": False,
            "dark_mode": True
        }

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {
            "last_csv": "",
            "update_db": False,
            "force_update": False,
            "dark_mode": True
        }


def save_settings(settings):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=4)
    except:
        pass



# ---------------------------------------------------------
# GUI Application Class
# ---------------------------------------------------------
class CVEProcessorGUI(ttk.Window):

    def __init__(self):
        # Load settings early so theme can be selected before creating the window
        self.settings = load_settings()
        theme = "darkly" if self.settings.get("dark_mode", True) else "flatly"
        super().__init__(themename=theme)
        self.title("Next-Generation CVE Processing Suite")
        self.geometry("900x650")
        self.resizable(False, False)

        self.cancel_flag = False

        # Keep a Tk variable for dark mode to bind to the settings UI
        self.dark_mode_var = tk.BooleanVar(value=self.settings.get("dark_mode", True))

        # ------------------ NOTEBOOK (TABS) -----------------------
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_process = ttk.Frame(notebook)
        self.tab_db = ttk.Frame(notebook)
        self.tab_settings = ttk.Frame(notebook)
        self.tab_logs = ttk.Frame(notebook)

        notebook.add(self.tab_process, text="Process CSV")
        notebook.add(self.tab_db, text="Database Tools")
        notebook.add(self.tab_settings, text="Settings")
        notebook.add(self.tab_logs, text="Logs")

        # Build each tab
        self.build_process_tab()
        self.build_db_tab()
        self.build_settings_tab()
        self.build_logs_tab()

        # Ensure NVD key exists
        self.ensure_nvd_key()

    def apply_theme(self, dark_mode: bool):
        try:
            style = ttk.Style()
            theme = "darkly" if dark_mode else "flatly"
            style.theme_use(theme)
        except Exception:
            pass

        # Adjust some widget colors that are not always theme-controlled
        try:
            if dark_mode:
                if hasattr(self, 'db_stats_box'):
                    self.db_stats_box.config(bg="#1E1E1E", fg="#00E0FF")
                if hasattr(self, 'log_text'):
                    self.log_text.config(bg="#1E1E1E", fg="#00FFAA", insertbackground="white")
            else:
                if hasattr(self, 'db_stats_box'):
                    self.db_stats_box.config(bg="white", fg="black")
                if hasattr(self, 'log_text'):
                    self.log_text.config(bg="white", fg="black", insertbackground="black")
        except Exception:
            pass

    def on_dark_mode_toggle(self):
        val = bool(self.dark_mode_var.get())
        self.settings["dark_mode"] = val
        save_settings(self.settings)
        self.apply_theme(val)



    # ---------------------------------------------------------
    # TAB: Process CSV
    # ---------------------------------------------------------
    def build_process_tab(self):
        frame = self.tab_process

        # Title
        ttk.Label(frame, text="CSV File Processor", font=("Segoe UI", 16, "bold")).pack(pady=10)

        # CSV Selection Row
        file_frame = ttk.Frame(frame)
        file_frame.pack(pady=10)

        ttk.Label(file_frame, text="CSV File:", font=("Segoe UI", 12)).grid(row=0, column=0, padx=5)

        self.csv_path_var = tk.StringVar(value=self.settings.get("last_csv", ""))

        self.csv_entry = ttk.Entry(file_frame, textvariable=self.csv_path_var, width=60)
        self.csv_entry.grid(row=0, column=1, padx=5)

        ttk.Button(file_frame, text="Browse", command=self.browse_file, bootstyle=PRIMARY).grid(row=0, column=2, padx=5)

        # Checkboxes
        self.update_db_var = tk.BooleanVar(value=self.settings.get("update_db", False))
        self.force_update_var = tk.BooleanVar(value=self.settings.get("force_update", False))

        ttk.Checkbutton(frame, text="Update DB Before Processing",
                        variable=self.update_db_var, bootstyle="success-round-toggle").pack(pady=5)

        ttk.Checkbutton(frame, text="Force Update DB",
                        variable=self.force_update_var, bootstyle="warning-round-toggle").pack(pady=5)

        # Progress Bar
        self.progress = ttk.Progressbar(frame, mode="determinate", length=600, bootstyle=INFO)
        self.progress.pack(pady=15)

        # Start and Cancel Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=5)

        ttk.Button(button_frame, text="Start Processing",
                   command=self.start_processing_thread,
                   bootstyle=SUCCESS).grid(row=0, column=0, padx=10)

        ttk.Button(button_frame, text="Cancel",
                   command=self.cancel_processing,
                   bootstyle=DANGER).grid(row=0, column=1, padx=10)



    # ---------------------------------------------------------
    # TAB: Database Tools
    # ---------------------------------------------------------
    def build_db_tab(self):
        frame = self.tab_db

        ttk.Label(frame, text="Database Maintenance Tools",
                font=("Segoe UI", 16, "bold")).pack(pady=10)

        # ------- Buttons -------
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Update Database", width=20, bootstyle=PRIMARY,
                command=lambda: self.run_db_update(force=False)).grid(row=0, column=0, padx=10)

        ttk.Button(btn_frame, text="Force Update Database", width=20, bootstyle=DANGER,
                command=lambda: self.run_db_update(force=True)).grid(row=0, column=1, padx=10)

        ttk.Button(btn_frame, text="Optimize (VACUUM)", width=20, bootstyle=SUCCESS,
                command=self.optimize_db).grid(row=0, column=2, padx=10)

        ttk.Separator(frame).pack(fill="x", pady=15)

        # -------- Database Statistics Panel --------
        ttk.Label(frame, text="Database Statistics",
                font=("Segoe UI", 14, "bold")).pack(pady=5)

        self.db_stats_box = tk.Text(
            frame,
            width=100, height=18,
            bg="#1E1E1E", fg="#00E0FF",
            font=("Consolas", 10),
            state="disabled"
        )
        self.db_stats_box.pack(padx=15, pady=10)

        ttk.Button(frame, text="Refresh Statistics", bootstyle=INFO,
                command=self.refresh_db_stats).pack(pady=5)

        # Load stats on start
        self.refresh_db_stats()

    def refresh_db_stats(self):
        stats = self.get_db_stats()

        self.db_stats_box.config(state="normal")
        self.db_stats_box.delete("1.0", "end")

        if not stats["exists"]:
            self.db_stats_box.insert("end", "⚠ Database file not found.\n")
            self.db_stats_box.config(state="disabled")
            return

        output = f"""
        📦 DATABASE STATISTICS — cve_cache.db
        ──────────────────────────────────────────────

        📁 File Size:           {stats['size_mb']} MB
        📚 Total CVE Entries:   {stats['total_records']}

        🥇 EPSS Cache:          {stats['epss_cache']}
        🥈 CVSS Cache:          {stats['cvss_cache']}

        📝 EPSS Detail Rows:    {stats['epss_detail']}
        📄 CVE Detail Rows:     {stats['cve_detail']}

        ⏱ Latest Cache Update: {stats['latest_update']}
        ⏳ Average Age:         {stats['avg_age_days']} days
        🔹 Newest Record Age:   {stats['newest_age']} days
        🔸 Oldest Record Age:   {stats['oldest_age']} days
        """

        self.db_stats_box.insert("end", output.strip())
        self.db_stats_box.config(state="disabled")

        self.log("[DB] Statistics refreshed.")


    # ---------------------------------------------------------
    # TAB: Settings
    # ---------------------------------------------------------
    def build_settings_tab(self):
        frame = self.tab_settings

        ttk.Label(frame, text="Application Settings", font=("Segoe UI", 16, "bold")).pack(pady=10)

        ttk.Button(frame, text="Reload Settings",
                   command=self.reload_settings, bootstyle=INFO).pack(pady=8)

        ttk.Button(frame, text="Reset Settings",
                   command=self.reset_settings, bootstyle=WARNING).pack(pady=8)

        ttk.Button(frame, text="Open Settings File",
                   command=lambda: os.startfile(SETTINGS_FILE), bootstyle=SECONDARY).pack(pady=8)

        # Dark mode toggle
        try:
            ttk.Checkbutton(
                frame,
                text="Dark Mode",
                variable=self.dark_mode_var,
                command=self.on_dark_mode_toggle,
                bootstyle="info-round-toggle"
            ).pack(pady=6)
        except Exception:
            # Fallback if bootstyle not supported
            ttk.Checkbutton(
                frame,
                text="Dark Mode",
                variable=self.dark_mode_var,
                command=self.on_dark_mode_toggle
            ).pack(pady=6)



    # ---------------------------------------------------------
    # TAB: Logs
    # ---------------------------------------------------------
    def build_logs_tab(self):
        frame = self.tab_logs

        ttk.Label(frame, text="Application Logs", font=("Segoe UI", 16, "bold")).pack(pady=10)

        self.log_text = tk.Text(frame, wrap="word", width=100, height=30,
                                bg="#1E1E1E", fg="#00FFAA",
                                insertbackground="white")
        self.log_text.pack(padx=10, pady=10)



    # ---------------------------------------------------------
    # Utility Functions
    # ---------------------------------------------------------
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if filename:
            self.csv_path_var.set(filename)
            self.log(f"[GUI] Selected CSV: {filename}")

    def log(self, msg):
        timestamp = datetime.now().isoformat(sep=' ', timespec='seconds')
        line = f"[{timestamp}] {msg}\n"
        try:
            if hasattr(self, 'log_text') and self.log_text:
                self.log_text.configure(state='normal')
                self.log_text.insert('end', line)
                self.log_text.see('end')
                self.log_text.configure(state='disabled')
            else:
                print(line, end='')
        except Exception:
            try:
                print(line, end='')
            except:
                pass

    def cancel_processing(self):
        self.cancel_flag = True
        self.log("[GUI] Cancel signal sent.")

    def start_processing_thread(self):
        threading.Thread(target=self.run_processing, daemon=True).start()

    def run_processing(self):
        csv_path = self.csv_path_var.get().strip()
        csv_path = os.path.normpath(csv_path)
        # messagebox.showinfo("File Path",csv_path)
        if not csv_path:
            messagebox.showerror("Error", "Please select a CSV file.")
            return

        # Save settings
        self.settings["last_csv"] = csv_path
        self.settings["update_db"] = self.update_db_var.get()
        self.settings["force_update"] = self.force_update_var.get()
        save_settings(self.settings)

        # DB Update if needed
        if self.update_db_var.get():
            force = self.force_update_var.get()
            self.run_db_update(force)

        # Reset cancel flag
        self.cancel_flag = False

        self.log(f"[PROCESS] Starting CSV processing: {csv_path}")
        self.progress.config(value=0)

        # Execute main processing
        try:
            process_and_update_csv(
                csv_path,
                progress_callback=self.update_progress,
                log_callback=self.log,
                cancel_check=lambda: self.cancel_flag
            )
        except Exception as e:
            self.log(f"[ERROR] {str(e)}")
            messagebox.showerror("Processing Error", str(e))
            return

        if self.cancel_flag:
            self.log("[PROCESS] Processing cancelled by user.")
            messagebox.showinfo("Cancelled", "Processing stopped.")
            return

        self.log("[PROCESS] Completed successfully.")
        messagebox.showinfo("Done", "CSV processing completed.")

    def update_progress(self, value, total):
        try:
            pct = (value / total) * 100
            self.progress.config(value=pct)
            self.update_idletasks()
        except:
            pass

    # ---------------------------------------------------------
    # DB Tools
    # ---------------------------------------------------------
    def run_db_update(self, force):
        self.log(f"[DB] Updating database (force={force})...")
        try:
            update_db(force)
            self.log("[DB] Update completed.")
            messagebox.showinfo("DB Update", "Database updated successfully.")
        except Exception as e:
            self.log(f"[ERROR] DB update failed: {str(e)}")
            messagebox.showerror("DB Error", str(e))

    def optimize_db(self):
        try:
            import sqlite3
            conn = sqlite3.connect("cve_cache.db")
            conn.execute("VACUUM")
            conn.close()
            self.log("[DB] VACUUM optimization completed.")
            messagebox.showinfo("DB Optimized", "Database optimized successfully.")
        except Exception as e:
            self.log(f"[ERROR] Database optimization failed: {e}")

    # ---------------------------------------------------------
    # Settings tab tools
    # ---------------------------------------------------------
    def reload_settings(self):
        self.settings = load_settings()
        self.csv_path_var.set(self.settings.get("last_csv", ""))
        self.update_db_var.set(self.settings.get("update_db", False))
        self.force_update_var.set(self.settings.get("force_update", False))
        self.log("[SETTINGS] Reloaded settings.")

    def reset_settings(self):
        if messagebox.askyesno("Reset Settings", "Reset all settings to default?"):
            self.settings = {
                "last_csv": "",
                "update_db": False,
                "force_update": False
            }
            save_settings(self.settings)
            self.reload_settings()
            self.log("[SETTINGS] Settings reset to default.")

    # ---------------------------------------------------------
    # DATABASE STATISTICS HELPER
    # ---------------------------------------------------------
    def get_db_stats(self):
        db_file = "cve_cache.db"
        stats = {
            "exists": os.path.exists(db_file),
            "size_mb": 0,
            "epss_cache": 0,
            "cvss_cache": 0,
            "epss_detail": 0,
            "cve_detail": 0,
            "total_records": 0,
            "latest_update": "N/A",
            "avg_age_days": 0,
            "newest_age": 0,
            "oldest_age": 0
        }

        if not stats["exists"]:
            return stats

        stats["size_mb"] = round(os.path.getsize(db_file) / (1024 * 1024), 3)

        conn = sqlite3.connect(db_file)
        cur = conn.cursor()

        def count(table):
            try:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                row = cur.fetchone()
                return row[0] if row and row[0] is not None else 0
            except Exception:
                return 0

        def get_dates(table):
            try:
                cur.execute(f"SELECT last_updated FROM {table}")
                rows = cur.fetchall()
                if not rows:
                    return []
                valid = []
                for r in rows:
                    try:
                        if r and r[0]:
                            valid.append(datetime.fromisoformat(r[0]))
                    except Exception:
                        pass
                return valid
            except Exception:
                return []

        # Count tables
        stats["epss_cache"] = count("epss_cache")
        stats["cvss_cache"] = count("cvss_cache")
        stats["epss_detail"] = count("epss_detail")
        stats["cve_detail"] = count("cve_detail")
        stats["total_records"] = stats["epss_cache"] + stats["cvss_cache"]

        # Timestamp analysis
        timestamps = []
        for table in ["epss_cache", "cvss_cache"]:
            timestamps.extend(get_dates(table))

        if timestamps:
            newest = max(timestamps)
            oldest = min(timestamps)
            now = datetime.now()

            stats["latest_update"] = newest.isoformat()
            stats["newest_age"] = (now - newest).days
            stats["oldest_age"] = (now - oldest).days
            stats["avg_age_days"] = round(
                sum((now - t).days for t in timestamps) / len(timestamps), 2
            )

        conn.close()
        return stats


    # ---------------------------------------------------------
    # NVD Key Handling
    # ---------------------------------------------------------
    def ensure_nvd_key(self):
        if not check_nvd_api_key():
            self.log("[NVD] Missing NVD API key.")
            messagebox.showwarning(
                "NVD API Key Missing",
                "No NVD API Key found.\nPlease enter your key."
            )
            key = prompt_and_store_nvd_key()
            if key:
                self.log("[NVD] New NVD API Key stored.")
            else:
                self.log("[NVD] No key entered. Processing may fail.")



# ---------------------------------------------------------
# Run GUI
# ---------------------------------------------------------
if __name__ == "__main__":
    app = CVEProcessorGUI()
    app.mainloop()
