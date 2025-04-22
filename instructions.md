# 🛡️ Instructions to Run & Test Signature-Based Host Intrusion Detection System (HIDS)

## 📋 Prerequisites

- Windows 10 or later
- Python 3.7+
- Admin rights (required for process monitoring and accessing protected files)
- Git (optional)

---

## ⚙️ Installation

Open **Command Prompt** or **PowerShell** as Administrator and run:

```bash
git clone https://github.com/yourusername/hids.git
cd hids
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

---

## 🛠️ Configuration

Edit the `config.ini` file to customize behavior:

```ini
[PATHS]
watch_paths = C:\Windows\System32;C:\Windows\SysWOW64
quarantine_dir = C:\HIDS_Quarantine

[FILTERS]
whitelisted_paths = C:\Windows\Temp
scan_extensions = .exe,.dll,.ps1
```

---

## 🚀 Running the HIDS

Run the app using:

```bash
python hids.py
```

Open the dashboard in your browser at:

```
http://localhost:5000
```

Use the buttons to:
- ✅ Start Monitoring
- 🔄 Clear Logs
- ⛔ Stop Monitoring

---

## 🧪 Testing with the Provided Sample

1. Ensure monitoring is **active**.
2. Copy the test file `test.ps1` into a monitored directory:

```powershell
copy .\test.ps1 "C:\Windows\System32\"
```

3. If the script matches a YARA rule:
   - You’ll hear an **audio alert**
   - The file may be **quarantined** (if enabled)
   - A message will show up under **Suspicious Activities**

---

## 📜 Logs

View detailed logs here:

```bash
notepad hids.log
```

Or check them directly from the dashboard.

---

## 🛑 Stopping the HIDS

- Use the "Stop Monitoring" button in the UI
- Or press `Ctrl + C` in the terminal to stop the server

---

## 🧯 Troubleshooting

- Run terminal as **Administrator**
- Make sure the test file:
  - Is in a monitored path
  - Has an extension included in `scan_extensions`
  - Contains detectable YARA patterns

---

## 🙋 Need Help?

Open an issue on [GitHub](https://github.com/yourusername/hids/issues) or email the maintainer.
