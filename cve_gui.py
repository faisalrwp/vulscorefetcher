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
            "force_update": False
        }

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {
            "last_csv": "",
            "update_db": False,
            "force_update": False
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
        super().__init__(themename="darkly")
        self.title("Next-Generation CVE Processing Suite")
        self.geometry("900x650")
        self.resizable(False, False)

        self.cancel_flag = False
        self.settings = load_settings()

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

        ttk.Label(frame, text="Database Maintenance Tools", font=("Segoe UI", 16, "bold")).pack(pady=10)

        ttk.Button(frame, text="Update Database", bootstyle=PRIMARY,
                   command=lambda: self.run_db_update(force=False)).pack(pady=10)

        ttk.Button(frame, text="Force Update Database", bootstyle=DANGER,
                   command=lambda: self.run_db_update(force=True)).pack(pady=10)

        ttk.Button(frame, text="Optimize (VACUUM)", bootstyle=SUCCESS,
                   command=self.optimize_db).pack(pady=10)



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
        self.log_text.insert("end", msg + "\n")
        self.log_text.see("end")

    def cancel_processing(self):
        self.cancel_flag = True
        self.log("[GUI] Cancel signal sent.")

    def start_processing_thread(self):
        threading.Thread(target=self.run_processing, daemon=True).start()

    def run_processing(self):
        csv_path = self.csv_path_var.get().strip()
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
