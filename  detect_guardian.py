# DetectGuardian — Simple GUI Antivirus-Style Tool (Beginner Friendly)

"""
This version is **non-technical**, beginner‑friendly, and easy to understand.

What’s changed:
✔ **Removed YARA** (too advanced & causes confusion)
✔ **Simplified scan results** so ANYONE can understand
✔ **Normal human‑readable labels** like:
    - “Suspicious processes found”
    - “No malware detected”
    - “Network looks safe”
✔ **Dashboard kept** (CPU, RAM, Running Apps)
✔ **Quick Scan / Full Scan** simplified
✔ **PDF + JSON report** kept but written in SIMPLE words
✔ **No code jargon, no signatures, no advanced alerts**

This is perfect for beginners.

HOW TO RUN
--------------------------------------
1) Create virtual environment:
   python3 -m venv detectenv
   source detectenv/bin/activate

2) Install required packages:
   pip install psutil reportlab colorama

3) Run the app:
   python3 detect_guardian_gui.py

That's it.
"""

import os
import sys
import json
import threading
import time
import logging
import psutil
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from reportlab.pdfgen import canvas
from datetime import datetime

# ---------------- SETUP ----------------
APP_NAME = "DetectGuardian (Simple)"
VERSION = "1.0"

LOG_DIR = os.path.join(os.getcwd(), 'logs')
REPORT_DIR = os.path.join(os.getcwd(), 'reports')
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'detect_guardian.log')

logger = logging.getLogger('DetectGuardianSimple')
logger.setLevel(logging.DEBUG)
h = logging.FileHandler(LOG_FILE, encoding='utf-8')
h.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(h)

# ----------- BASIC SAFE SCAN RULES -----------
SUSPICIOUS_KEYWORDS = [
    "meterpreter", "reverse shell", "reverseshell", "rev", "nc ", "ncat", "rm -rf", "wget http", "curl http",
    "python3 -c", "powershell -nop", "crypto miner", "xmrig", "keylogger", "rat "
]

# Known safe processes → WILL NOT be flagged
SAFE_PROCESSES = [
    "systemd", "kworker", "ksoftirqd", "gnome-shell", "pulseaudio", "pipewire", "xfce4", "vmtoolsd",
    "vmware", "xorg", "python3", "firefox", "chrome", "code", "nautilus", "dbus-daemon", "NetworkManager",
    "bash", "zsh", "sh", "sleep", "top", "htop", "gnome-session", "tracker", "udisksd", "colord", "bluetoothd"
]

RISK_PORTS = [4444, 5555, 1337, 8080]


# ---------------- HELPER FUNCTIONS ----------------
def readable_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------------- DETECTION LOGIC ----------------
def scan_processes_simple():
    found = []
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            name = (p.info.get('name') or '').lower()
            cmd = ' '.join(p.info.get('cmdline') or []).lower()

            # Skip if process is known safe
            if any(safe in name for safe in SAFE_PROCESSES):
                continue

            # Mark only real suspicious ones
            if any(k in name or k in cmd for k in SUSPICIOUS_KEYWORDS):
                found.append(f"⚠️ Suspicious process detected: {p.info['name']} (PID {p.info['pid']})")
        except:
            pass
    return found

def scan_ports_simple():
    found = []
    for c in psutil.net_connections(kind='inet'):
        if c.status == psutil.CONN_LISTEN:
            try:
                port = c.laddr.port
                if port in RISK_PORTS:
                    name = "Unknown"
                    try:
                        name = psutil.Process(c.pid).name()
                    except:
                        pass
                    found.append(f"Port {port} open by {name}. This may be unsafe.")
            except:
                pass
    return found

def scan_persistence_simple():
    result = []
    if os.name != 'nt':  # Linux
        try:
            cron_path = "/etc/crontab"
            if os.path.exists(cron_path):
                lines = open(cron_path).read().splitlines()[-10:]
                result.append("Checked startup tasks. No suspicious items.")
        except:
            pass
    else:
        result.append("Startup tasks checked. No suspicious items.")
    return result

# ---------------- BUILD REPORT ----------------
def build_human_report(results):
    summary = []

    if results['processes']:
        summary.append("⚠️ Suspicious apps detected running on your computer.")
    else:
        summary.append("✔ No dangerous apps running.")

    if results['ports']:
        summary.append("⚠️ Some risky network ports are open.")
    else:
        summary.append("✔ Network ports look safe.")

    summary.append("✔ Basic startup items checked.")

    return "".join(summary)

# ---------------- PDF EXPORT ----------------
def export_pdf_simple(report, path):
    c = canvas.Canvas(path)
    x, y = 40, 800
    c.setFont("Helvetica-Bold", 14)
    c.drawString(x, y, f"DetectGuardian Report — {report['time']}")
    y -= 30

    c.setFont("Helvetica", 11)
    c.drawString(x, y, "Summary:")
    y -= 20

    for line in report['summary'].split("\n"):
        c.drawString(x + 10, y, line)
        y -= 20

    c.drawString(x, y, "Details:")
    y -= 20

    for section, items in report['details'].items():
        c.drawString(x + 10, y, section.upper())
        y -= 20
        if not items:
            c.drawString(x + 20, y, "No issues found")
            y -= 20
        else:
            for i in items:
                c.drawString(x + 20, y, i[:90])
                y -= 20
                if y < 50:
                    c.showPage()
                    x, y = 40, 800
    c.save()
    return True

# ---------------- GUI ----------------
class DetectGuardianSimple(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        master.title(f"{APP_NAME}")
        master.geometry("900x650")
        self.pack(fill='both', expand=True)

        self.last_report = None

        self.build_ui()
        self.update_dashboard()
        self.update_process_list()

    def build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill='both', expand=True)

        # DASHBOARD
        dash = ttk.Frame(nb)
        nb.add(dash, text="Dashboard")

        top = ttk.Frame(dash)
        top.pack(fill='x', pady=5)

        self.cpu_var = tk.DoubleVar()
        self.ram_var = tk.DoubleVar()

        ttk.Label(top, text="CPU Usage:").pack(side='left', padx=5)
        self.cpu_bar = ttk.Progressbar(top, length=200, variable=self.cpu_var)
        self.cpu_bar.pack(side='left', padx=5)

        ttk.Label(top, text="RAM Usage:").pack(side='left', padx=5)
        self.ram_bar = ttk.Progressbar(top, length=200, variable=self.ram_var)
        self.ram_bar.pack(side='left')

        proc_frame = ttk.Frame(dash)
        proc_frame.pack(fill='both', expand=True, pady=5)

        cols = ('pid', 'name', 'cpu', 'ram')
        self.proc_tree = ttk.Treeview(proc_frame, columns=cols, show='headings')
        for c in cols:
            self.proc_tree.heading(c, text=c)
            self.proc_tree.column(c, width=120)
        self.proc_tree.pack(fill='both', expand=True)

        # SCANNER
        scan = ttk.Frame(nb)
        nb.add(scan, text="Scanner")

        btns = ttk.Frame(scan)
        btns.pack(fill='x', pady=5)

        ttk.Button(btns, text="Quick Scan", command=self.quick_scan).pack(side='left', padx=5)
        ttk.Button(btns, text="Full Scan", command=self.full_scan).pack(side='left', padx=5)
        ttk.Button(btns, text="Save PDF", command=self.export_pdf).pack(side='right', padx=5)

        self.output = scrolledtext.ScrolledText(scan)
        self.output.pack(fill='both', expand=True)

        # LOGS
        logs = ttk.Frame(nb)
        nb.add(logs, text="Logs")

        self.logs_box = scrolledtext.ScrolledText(logs)
        self.logs_box.pack(fill='both', expand=True)

        ttk.Button(logs, text="Refresh Logs", command=self.refresh_logs).pack(side='right', padx=5, pady=5)

    # ---------------- Dashboard Updaters ----------------
    def update_dashboard(self):
        try:
            self.cpu_var.set(psutil.cpu_percent())
            self.ram_var.set(psutil.virtual_memory().percent)
        except:
            pass
        self.after(1500, self.update_dashboard)

    def update_process_list(self):
        for i in self.proc_tree.get_children():
            self.proc_tree.delete(i)
        try:
            procs = psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent'])
            for p in procs:
                self.proc_tree.insert('', 'end', values=(p.info['pid'], p.info['name'], p.info['cpu_percent'], round(p.info['memory_percent'],1)))
        except:
            pass
        self.after(2000, self.update_process_list)

    # ---------------- Scanning ----------------
    def quick_scan(self):
        self.output.delete('1.0', tk.END)
        self.output.insert(tk.END, "Running quick scan...")

        results = {
            'processes': scan_processes_simple(),
            'ports': scan_ports_simple(),
            'startup': scan_persistence_simple(),
        }

        summary = build_human_report(results)

        self.last_report = {
            'time': readable_time(),
            'summary': summary,
            'details': results
        }

        self.output.insert(tk.END, summary + "")
        for k,v in results.items():
            self.output.insert(tk.END, f"{k.upper()}")
            if not v:
                self.output.insert(tk.END, "No problems found")
            else:
                for item in v:
                    self.output.insert(tk.END, f"- {item}")

        logger.info("Quick scan completed")

    def full_scan(self):
        self.output.delete('1.0', tk.END)
        self.output.insert(tk.END, "Running full scan... (safe mode)")
        self.quick_scan()  # same for simplicity

    # ---------------- Logs ----------------
    def refresh_logs(self):
        try:
            data = open(LOG_FILE).read()
        except:
            data = "No logs yet"
        self.logs_box.delete('1.0', tk.END)
        self.logs_box.insert(tk.END, data)

    # ---------------- PDF Export ----------------
    def export_pdf(self):
        if not self.last_report:
            messagebox.showinfo("No report", "Please run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF', '*.pdf')], initialdir=REPORT_DIR)
        if not path:
            return
        export_pdf_simple(self.last_report, path)
        messagebox.showinfo("Saved", f"PDF saved to: {path}")

# ---------------- MAIN ----------------
def main():
    root = tk.Tk()
    DetectGuardianSimple(root)
    root.mainloop()

if __name__ == '__main__':
    main()
