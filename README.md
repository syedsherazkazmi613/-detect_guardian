# DetectGuardian — Simple GUI Antivirus-Style Tool

A beginner-friendly, non-technical antivirus-style tool with a simple GUI that helps you monitor your system's security status. DetectGuardian scans for suspicious processes, risky network ports, and startup items, providing easy-to-understand results.

## Features

- **Dashboard**: Real-time monitoring of CPU and RAM usage, plus a list of running processes
- **Quick Scan**: Fast scan for suspicious processes, network ports, and startup items
- **Full Scan**: Comprehensive system scan (currently same as Quick Scan)
- **PDF Reports**: Export scan results as PDF reports
- **Simple Interface**: User-friendly GUI with clear, human-readable messages
- **Cross-Platform**: Works on both Windows and Linux

## Requirements

- Python 3.6 or higher
- tkinter (usually included with Python)
- Required Python packages:
  - `psutil` - System and process utilities
  - `reportlab` - PDF generation
  - `colorama` - Cross-platform colored terminal text (optional)

## Installation

### Linux

1. **Clone or download this repository:**
   ```bash
   cd /path/to/py
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python3 -m venv detectenv
   ```

3. **Activate the virtual environment:**
   ```bash
   source detectenv/bin/activate
   ```

4. **Install required packages:**
   ```bash
   pip install psutil reportlab colorama
   ```

   Or if you prefer to upgrade pip first:
   ```bash
   pip install --upgrade pip
   pip install psutil reportlab colorama
   ```

### Windows

1. **Open Command Prompt or PowerShell** and navigate to the project directory:
   ```cmd
   cd C:\path\to\py
   ```

2. **Create a virtual environment (recommended):**
   ```cmd
   python -m venv detectenv
   ```
   
   Or using PowerShell:
   ```powershell
   python -m venv detectenv
   ```

3. **Activate the virtual environment:**
   
   **For Command Prompt:**
   ```cmd
   detectenv\Scripts\activate
   ```
   
   **For PowerShell:**
   ```powershell
   detectenv\Scripts\Activate.ps1
   ```
   
   If you get an execution policy error in PowerShell, run:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. **Install required packages:**
   ```cmd
   pip install psutil reportlab colorama
   ```

   Or if you prefer to upgrade pip first:
   ```cmd
   python -m pip install --upgrade pip
   pip install psutil reportlab colorama
   ```

## Running the Application

### Linux

1. **Make sure the virtual environment is activated** (you should see `(detectenv)` in your terminal prompt)

2. **Run the application:**
   ```bash
   python3 des.py
   ```

   Or if `python3` is not available:
   ```bash
   python des.py
   ```

### Windows

1. **Make sure the virtual environment is activated** (you should see `(detectenv)` in your command prompt)

2. **Run the application:**
   ```cmd
   python des.py
   ```

## Usage

1. **Dashboard Tab**: View real-time CPU and RAM usage, and browse running processes
2. **Scanner Tab**: 
   - Click "Quick Scan" for a fast security scan
   - Click "Full Scan" for a comprehensive scan
   - Click "Save PDF" to export the last scan results as a PDF report
3. **Logs Tab**: View application logs and click "Refresh Logs" to update

## Project Structure

```
py/
├── detect_guardian.py              # Main application file
├── detectenv/          # Virtual environment (created during setup)
├── logs/               # Application logs directory (auto-created)
│   └── detect_guardian.log
├── reports/            # PDF reports directory (auto-created)
└── README.md           # This file
```

## Notes

- The application requires administrator/root privileges for some system scans (especially on Linux)
- Logs and reports are automatically saved in the `logs/` and `reports/` directories
- The tool uses simple keyword-based detection and is designed for educational purposes
- This is a simplified, beginner-friendly version that focuses on ease of use over advanced detection

## Troubleshooting

### Linux Issues

**Issue: tkinter not found**
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch Linux
sudo pacman -S tk
```

**Issue: Permission denied for system scans**
- Some scans may require elevated privileges. Run with `sudo` if needed (though this is not recommended for GUI applications)

### Windows Issues

**Issue: Python not recognized**
- Make sure Python is installed and added to PATH
- Download Python from [python.org](https://www.python.org/downloads/)
- During installation, check "Add Python to PATH"

**Issue: tkinter not available**
- Reinstall Python and make sure to select "tcl/tk and IDLE" during installation

**Issue: PowerShell execution policy**
- If you get an execution policy error when activating the virtual environment, run:
  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

## License

This project is provided as-is for educational purposes.

## Version

Current version: 1.0

