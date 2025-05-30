import os
import sys
import time
import threading
import win32api
import win32con
import win32evtlog
import win32security
import pythoncom
import wmi
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import yara
import configparser
import logging
from logging.handlers import RotatingFileHandler
import ctypes
from ctypes import wintypes
import re
from collections import defaultdict
from flask import Flask, jsonify, render_template, request

# Configure logging
log_handler = RotatingFileHandler('hids.log', maxBytes=1_000_000, backupCount=3)
logging.basicConfig(
    handlers=[log_handler],
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__, template_folder='templates', static_folder='static')

# Windows API Process Monitoring
class ProcessMonitor:
    def __init__(self):
        self.PROCESS_QUERY_INFORMATION = 0x0400
        self.PROCESS_VM_READ = 0x0010
        self.MAX_PROCESSES = 1024
        self.last_processes = set()

    def get_process_list(self):
        """Get current running processes using Windows API"""
        process_ids = (wintypes.DWORD * self.MAX_PROCESSES)()
        cb_needed = wintypes.DWORD()
        if not ctypes.windll.psapi.EnumProcesses(
            ctypes.byref(process_ids),
            ctypes.sizeof(process_ids),
            ctypes.byref(cb_needed)
        ):
            logging.error("Failed to enumerate processes")
            return set()
        count = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
        return set(process_ids[:count])

    def get_process_name(self, pid):
        """Get process name by PID using Windows API"""
        hProcess = ctypes.windll.kernel32.OpenProcess(
            self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ,
            False, pid)
        if hProcess:
            try:
                buf = ctypes.create_string_buffer(1024)
                size = ctypes.c_ulong(ctypes.sizeof(buf))
                if ctypes.windll.psapi.GetModuleBaseNameA(
                    hProcess, None, ctypes.byref(buf), ctypes.byref(size)):
                    return buf.value.decode('utf-8')
            finally:
                ctypes.windll.kernel32.CloseHandle(hProcess)
        return None

    def detect_new_processes(self):
        """Detect newly created processes"""
        current_processes = self.get_process_list()
        new_processes = current_processes - self.last_processes
        self.last_processes = current_processes
        return new_processes

    def get_parent_pid(self, pid):
        """Get parent process ID using Windows API"""
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260)
            ]
        TH32CS_SNAPPROCESS = 0x00000002
        hSnapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        parent_pid = None
        if ctypes.windll.kernel32.Process32First(hSnapshot, ctypes.byref(entry)):
            while True:
                if entry.th32ProcessID == pid:
                    parent_pid = entry.th32ParentProcessID
                    break
                if not ctypes.windll.kernel32.Process32Next(hSnapshot, ctypes.byref(entry)):
                    break
        ctypes.windll.kernel32.CloseHandle(hSnapshot)
        return parent_pid

# Enable SeDebugPrivilege
def enable_privilege(privilege_name):
    try:
        flags = win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
        privilege_id = win32security.LookupPrivilegeValue(None, privilege_name)
        win32security.AdjustTokenPrivileges(token, False, [(privilege_id, win32con.SE_PRIVILEGE_ENABLED)])
        logging.info(f"Privilege {privilege_name} enabled successfully")
        return True
    except Exception as e:
        logging.error(f"Failed to enable privilege {privilege_name}: {str(e)}")
        return False

# YARA rules
yara_rules = r"""
import "pe"

rule malicious_script {
    meta:
        description = "Detects malicious PowerShell patterns"
        severity = "high"
    strings:
        $ps1 = "powershell" nocase
        $iex1 = /Invoke-Expression\s+\(.*DownloadString/ nocase
        $iex2 = /iex\s+\(.*DownloadString/ nocase
        $webclient = /New-Object\s+Net\.WebClient.*Download/ nocase
        $hidden = /Start-Process\s+-WindowStyle\s+Hidden/ nocase
        $base64 = /FromBase64String\s*\(/ nocase
    condition:
        $ps1 and (
            ($iex1 or $iex2) or
            ($webclient and $hidden) or
            ($base64 and filesize < 50KB)
        )
}

rule suspicious_executable {
    meta:
        description = "Detects suspicious executables"
        severity = "critical"
    strings:
        $mz = "MZ"
        $s1 = "mimikatz" nocase wide
        $s2 = "cobaltstrike" nocase wide
        $s3 = "empire" nocase wide
        $s4 = /powershell.*-nop.*-w\s+hidden/ nocase
    condition:
        $mz at 0 and (
            any of ($s*) or
            (pe.imports("Advapi32.dll", "OpenProcessToken") and
             pe.imports("Advapi32.dll", "AdjustTokenPrivileges"))
        )
}

rule temp_executable {
    meta:
        description = "Detects executables in temp folders"
        severity = "medium"
    strings:
        $temp1 = /\\Temp\\/ nocase
        $temp2 = /\\Temporary\\/ nocase
        $temp3 = /AppData\\Local\\Temp\\/ nocase
    condition:
        uint32(0) == 0x5A4D and
        any of ($temp*) and
        filesize < 10MB
}
"""

class RegistryMonitor:
    def __init__(self, hids):
        self.hids = hids
        self.suspicious_keys = []
        if hids.config.has_option('ANOMALY', 'suspicious_registry_keys'):
            self.suspicious_keys = [
                x.strip() for x in hids.config.get('ANOMALY', 'suspicious_registry_keys').split(',')
            ]

    def monitor_registry(self):
        pythoncom.CoInitialize()
        c = wmi.WMI()
        watcher = c.Win32_RegistryKey.watch_for(
            notification_type="Modification",
            delay_secs=5
        )
        while self.hids.monitoring_active:
            try:
                change = watcher()
                if change.Name in self.suspicious_keys:
                    self.analyze_reg_change(change)
            except Exception as e:
                logging.error(f"Registry monitor error: {str(e)}")

    def analyze_reg_change(self, change):
        alert_msg = f"SUSPICIOUS REGISTRY MODIFICATION: {change.Name}"
        logging.warning(alert_msg)
        self.hids.suspicious_activities.append({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'message': alert_msg
        })

class HIDS:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.monitoring_active = False
        enable_privilege(win32con.SE_DEBUG_NAME)
        try:
            self.rules = yara.compile(source=yara_rules)
            logging.info("YARA rules compiled successfully")
        except Exception as e:
            logging.error(f"YARA compilation error: {str(e)}")
            sys.exit(1)
        self.suspicious_activities = []
        self.wmi_conn = None
        self.process_monitor = ProcessMonitor()
        self.last_alert_time = {}
        self.whitelist = self.load_whitelist()
        self.observer = None

        # Anomaly detection state
        self.behavior_baseline = {
            'process_tree': defaultdict(int)
        }
        self.learning_mode = True
        self.learning_duration = int(self.config.get('ANOMALY', 'learning_duration', fallback=3600))
        self.anomaly_detection = self.config.getboolean('MONITORING', 'anomaly_detection', fallback=True)
        self.registry_monitor = RegistryMonitor(self)

        try:
            pythoncom.CoInitialize()
            self.wmi_conn = wmi.WMI()
            logging.info("WMI initialized successfully")
        except Exception as e:
            logging.warning(f"WMI initialization failed, using Windows API fallback: {str(e)}")

    def build_baseline(self):
        logging.info("Building behavior baseline for anomaly detection...")
        start_time = time.time()
        while time.time() - start_time < self.learning_duration:
            processes = self.process_monitor.get_process_list()
            for pid in processes:
                name = self.process_monitor.get_process_name(pid)
                parent_pid = self.process_monitor.get_parent_pid(pid)
                parent_name = self.process_monitor.get_process_name(parent_pid)
                key = f"{parent_name}->{name}"
                self.behavior_baseline['process_tree'][key] += 1
            time.sleep(5)
        self.learning_mode = False
        logging.info(f"Baseline established with {len(self.behavior_baseline['process_tree'])} process relationships")

    def load_whitelist(self):
        whitelist = {
            'paths': [
                r'C:\\Windows\\System32\\DriverStore\\',
                r'C:\\Windows\\Temp\\',
                r'AppData\\Local\\Temp\\',
                r'\\$Recycle.Bin\\',
                r'\\AMD\\EeuDumps\\',
                r'\\Microsoft\\Edge\\User Data\\',
                r'\\Spotify\\Users\\'
            ],
            'processes': [
                'svchost.exe',
                'explorer.exe',
                'notepad.exe',
                'chrome.exe',
                'msedge.exe',
                'winlogon.exe'
            ],
            'extensions': ['.exe', '.dll', '.ps1', '.vbs', '.js', '.bat', '.cmd']
        }
        if self.config.has_option('FILTERS', 'whitelisted_paths'):
            whitelist['paths'].extend(
                [x.strip() for x in self.config.get('FILTERS', 'whitelisted_paths').split(';')]
            )
        if self.config.has_option('FILTERS', 'whitelisted_processes'):
            whitelist['processes'].extend(
                [x.strip() for x in self.config.get('FILTERS', 'whitelisted_processes').split(',')]
            )
        if self.config.has_option('FILTERS', 'scan_extensions'):
            whitelist['extensions'] = [
                x.strip() for x in self.config.get('FILTERS', 'scan_extensions').split(',')
            ]
        return whitelist

    def is_whitelisted(self, path_or_name):
        if not path_or_name:
            return False
        path_or_name = path_or_name.lower()
        if any(re.search(rf'\\{p.lower()}$', path_or_name) or
               path_or_name.endswith(p.lower()) for p in self.whitelist['processes']):
            return True
        if any(p.lower() in path_or_name for p in self.whitelist['paths']):
            return True
        return False

    def should_scan_file(self, file_path):
        if not file_path:
            return False
        file_path = file_path.lower()
        if self.is_whitelisted(file_path):
            return False
        if not any(file_path.endswith(ext) for ext in self.whitelist['extensions']):
            return False
        if file_path in self.last_alert_time:
            if time.time() - self.last_alert_time[file_path] < 60:
                return False
        return True

    def start_monitoring(self):
        if self.monitoring_active:
            return False
        self.monitoring_active = True
        logging.info("Starting HIDS monitoring")
        if self.config.getboolean('MONITORING', 'filesystem', fallback=True):
            self.start_file_monitor()
        if self.config.getboolean('MONITORING', 'processes', fallback=True):
            if self.wmi_conn:
                self.start_wmi_process_monitor()
            else:
                self.start_api_process_monitor()
        if self.config.getboolean('MONITORING', 'periodic_scans', fallback=True):
            self.start_periodic_scans()
        # Start registry anomaly monitor
        # if self.anomaly_detection:
        #     threading.Thread(target=self.registry_monitor.monitor_registry, daemon=True).start()
        # return True
    
    def stop_monitoring(self):
        if not self.monitoring_active:
            return False
        self.monitoring_active = False
        logging.info("Stopping HIDS monitoring")
        if hasattr(self, 'observer') and self.observer:
            self.observer.stop()
            self.observer.join()
        return True

    def clear_logs(self):
        self.suspicious_activities = []
        logging.info("Cleared suspicious activities log")
        return True

    def start_file_monitor(self):
        paths = self.config.get('PATHS', 'watch_paths', fallback="C:\\Windows\\System32;C:\\Windows\\SysWOW64").split(';')
        event_handler = FileSystemEventHandler()
        event_handler.on_modified = self.on_file_modified
        event_handler.on_created = self.on_file_created
        self.observer = Observer()
        for path in paths:
            if os.path.exists(path):
                try:
                    self.observer.schedule(event_handler, path, recursive=True)
                    logging.info(f"Monitoring path: {path}")
                except Exception as e:
                    logging.error(f"Failed to monitor path {path}: {str(e)}")
        try:
            self.observer.start()
            logging.info("File system monitoring started")
        except Exception as e:
            logging.error(f"Failed to start file monitor: {str(e)}")

    def on_file_modified(self, event):
        try:
            if not event.is_directory and self.should_scan_file(event.src_path):
                logging.debug(f"Scanning modified file: {event.src_path}")
                self.analyze_file(event.src_path, "modified")
        except Exception as e:
            logging.error(f"Error in on_file_modified: {str(e)}")

    def on_file_created(self, event):
        try:
            if not event.is_directory and self.should_scan_file(event.src_path):
                logging.debug(f"Scanning created file: {event.src_path}")
                self.analyze_file(event.src_path, "created")
        except Exception as e:
            logging.error(f"Error in on_file_created: {str(e)}")

    def start_wmi_process_monitor(self):
        def wmi_monitor():
            try:
                interval = int(self.config.get('MONITORING', 'process_check_interval', fallback=5))
                watcher = self.wmi_conn.Win32_Process.watch_for(
                    notification_type="Creation",
                    delay_secs=interval
                )
                logging.info("WMI process monitor started")
                while self.monitoring_active:
                    try:
                        new_process = watcher()
                        if new_process and not self.is_whitelisted(new_process.Name):
                            self.analyze_process(new_process.Name, new_process.ProcessId, new_process.ExecutablePath)
                    except pythoncom.com_error as e:
                        logging.error(f"WMI monitor error: {str(e)}")
                        time.sleep(interval)
            except Exception as e:
                logging.error(f"Unexpected WMI error: {str(e)}")
                time.sleep(1)
        threading.Thread(target=wmi_monitor, daemon=True, name="WMIProcessMonitor").start()

    def start_api_process_monitor(self):
        def api_monitor():
            interval = int(self.config.get('MONITORING', 'process_check_interval', fallback=5))
            logging.info("Windows API process monitor started")
            self.process_monitor.last_processes = self.process_monitor.get_process_list()
            while self.monitoring_active:
                try:
                    new_pids = self.process_monitor.detect_new_processes()
                    for pid in new_pids:
                        name = self.process_monitor.get_process_name(pid)
                        if name and not self.is_whitelisted(name):
                            self.analyze_process(name, pid, None)
                    time.sleep(interval)
                except Exception as e:
                    logging.error(f"API monitor error: {str(e)}")
                    time.sleep(interval)
        threading.Thread(target=api_monitor, daemon=True, name="APIProcessMonitor").start()

    def analyze_process(self, name, pid, path):
        try:
            proc_info = f"{name}|||{path if path else 'unknown'}".encode()
            matches = self.rules.match(data=proc_info)
            # Anomaly detection
            if self.anomaly_detection and not self.learning_mode:
                self.detect_process_anomalies(name, pid, path)
            if matches:
                alert_msg = f"SUSPICIOUS PROCESS: {name} (PID: {pid}) - Matches: {', '.join([str(m) for m in matches])}"
                logging.warning(alert_msg)
                self.suspicious_activities.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'message': alert_msg
                })
                if self.config.getboolean('RESPONSE', 'kill_process', fallback=False):
                    self.terminate_process(pid)
        except Exception as e:
            logging.error(f"Error analyzing process {name}: {str(e)}")

    def detect_process_anomalies(self, name, pid, path):
        parent_pid = self.process_monitor.get_parent_pid(pid)
        parent_name = self.process_monitor.get_process_name(parent_pid)
        process_key = f"{parent_name}->{name}"
        # Process tree anomaly
        if not self.behavior_baseline['process_tree'].get(process_key, 0):
            self.trigger_alert(f"ANOMALOUS PROCESS TREE: {process_key}")
        # Temporal anomaly
        current_hour = time.localtime().tm_hour
        late_hours = [int(x) for x in self.config.get('ANOMALY', 'late_night_hours', fallback="23,0,1,2,3,4,5").split(',')]
        if current_hour in late_hours:
            self.trigger_alert(f"LATE-NIGHT PROCESS: {name} @ {current_hour}:00")

    def trigger_alert(self, message):
        logging.warning(message)
        self.suspicious_activities.append({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'message': message
        })

    def analyze_file(self, file_path, action):
        try:
            matches = self.rules.match(filepath=file_path)
            if matches:
                self.last_alert_time[file_path] = time.time()
                alert_msg = f"SUSPICIOUS FILE {action}: {file_path} - Matches: {', '.join([str(m) for m in matches])}"
                logging.warning(alert_msg)
                self.suspicious_activities.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'message': alert_msg
                })
                if self.config.getboolean('RESPONSE', 'quarantine', fallback=False):
                    self.quarantine_file(file_path)
        except yara.Error as e:
            if "could not open file" not in str(e):
                logging.error(f"YARA error analyzing {file_path}: {str(e)}")
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {str(e)}")

    def quarantine_file(self, file_path):
        quarantine_dir = self.config.get('PATHS', 'quarantine_dir', fallback="C:\\HIDS_Quarantine")
        os.makedirs(quarantine_dir, exist_ok=True)
        try:
            dest = os.path.join(quarantine_dir, os.path.basename(file_path))
            if os.path.exists(dest):
                dest = dest + "_" + str(int(time.time()))
            os.rename(file_path, dest)
            logging.warning(f"QUARANTINED file {file_path} to {dest}")
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {str(e)}")

    def terminate_process(self, pid):
        try:
            os.kill(pid, 9)
            logging.warning(f"TERMINATED process with PID: {pid}")
        except Exception as e:
            logging.error(f"Failed to terminate process {pid}: {str(e)}")

    def start_periodic_scans(self):
        def scan_job():
            interval = int(self.config.get('MONITORING', 'scan_interval', fallback=3600))
            while self.monitoring_active:
                logging.info("Starting periodic scan")
                self.scan_critical_files()
                time.sleep(interval)
        scan_thread = threading.Thread(target=scan_job, daemon=True, name="PeriodicScan")
        scan_thread.start()

    def scan_critical_files(self):
        critical_files = [
            "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "C:\\Windows\\System32\\wscript.exe",
            "C:\\Windows\\System32\\cscript.exe",
            "C:\\Windows\\System32\\schtasks.exe",
            "C:\\Windows\\System32\\regsvr32.exe"
        ]
        for file in critical_files:
            if os.path.exists(file) and not self.is_whitelisted(file):
                self.analyze_file(file, "periodic scan")

    def get_status(self):
        paths = self.config.get('PATHS', 'watch_paths', fallback="C:\\Windows\\System32;C:\\Windows\\SysWOW64").split(';')
        return {
            'monitoring': self.monitoring_active,
            'paths': '\n'.join(paths),
            'activities': self.suspicious_activities[-20:]
        }

# Flask API endpoints
hids = HIDS()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def status():
    return jsonify(hids.get_status())

@app.route('/api/start', methods=['POST'])
def start():
    success = hids.start_monitoring()
    return jsonify({'success': success, 'message': 'Monitoring started' if success else 'Monitoring already active'})

@app.route('/api/stop', methods=['POST'])
def stop():
    success = hids.stop_monitoring()
    return jsonify({'success': success, 'message': 'Monitoring stopped' if success else 'Monitoring already stopped'})

@app.route('/api/clear', methods=['POST'])
def clear():
    success = hids.clear_logs()
    return jsonify({'success': success, 'message': 'Logs cleared' if success else 'Failed to clear logs'})

if __name__ == "__main__":
    # If run with --learn, build anomaly baseline
    if '--learn' in sys.argv:
        hids.build_baseline()
        print("Baseline learning complete. Restart HIDS in normal mode.")
        sys.exit(0)
    app.run(host="0.0.0.0", port=5000, debug=False)
