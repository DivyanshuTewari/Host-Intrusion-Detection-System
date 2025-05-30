# Host Intrusion Detection System (HIDS)

A Windows-based **Signature-Based Host Intrusion Detection System (HIDS)** that monitors the file system and process activities for suspicious behavior using YARA rules. It provides a modern web-based GUI and supports real-time alerts, configurable scanning, and process/file quarantine features.

## 🌐 Features

- 🕵️ Real-time **file and process monitoring**
- ⚠️ Detection of malicious patterns via **YARA signatures**
- 📦 **Quarantine** suspicious files
- 🚫 Optional **process termination** for malicious activities
- 🔁 **Periodic scanning** of critical system files
- 🌈 Clean **Web UI** to visualize monitoring, logs, and controls
- ⚙️ Highly **configurable** via `config.ini`
- 📝 Detailed **logging** with rotation support

---

## 🖥️ GUI Overview

The web interface (built using Flask + JS/CSS) allows users to:

- View monitoring status
- See recent suspicious activity logs
- Start/Stop monitoring
- Clear detection logs

![HIDS GUI Screenshot]


![Screenshot 2025-04-22 210750](https://github.com/user-attachments/assets/909f7f5e-8db1-4dfe-a825-040a1feb0681)


---

## 🧱 Project Structure

```plaintext
.
├── hids.py              # Main application logic and API endpoints
├── signatures.py        # YARA rules used for detection
├── config.ini           # Configuration file
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # HTML for the web GUI
├── static/
│   ├── style.css        # Web GUI styling
│   ├── script.js        # Client-side behavior
│   ├── shield.png       # Icon used in GUI
│   └── alert.mp3        # Audio alert for detections
└── hids.log             # Auto-generated log file (after running)
