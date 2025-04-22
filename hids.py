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

# Enhanced YARA rules with fewer false positives
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

class HIDS:
    def __init__(self):
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        self.monitoring_active = False

        # Enable required privileges
        enable_privilege(win32con.SE_DEBUG_NAME)

        # Initialize detection components
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
        
        # Initialize WMI (primary method)
        try:
            pythoncom.CoInitialize()
            self.wmi_conn = wmi.WMI()
            logging.info("WMI initialized successfully")
        except Exception as e:
            logging.warning(f"WMI initialization failed, using Windows API fallback: {str(e)}")

    def load_whitelist(self):
        """Load whitelisted paths/processes from config"""
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
        
        # Add config file overrides
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
        """Check if item is whitelisted"""
        if not path_or_name:
            return False
            
        path_or_name = path_or_name.lower()
        
        # Check processes
        if any(re.search(rf'\\{p.lower()}$', path_or_name) or 
               path_or_name.endswith(p.lower()) for p in self.whitelist['processes']):
            return True
            
        # Check paths
        if any(p.lower() in path_or_name for p in self.whitelist['paths']):
            return True
            
        return False

    def should_scan_file(self, file_path):
        """Determine if a file should be scanned"""
        if not file_path:
            return False
            
        file_path = file_path.lower()
        
        # Skip whitelisted paths
        if self.is_whitelisted(file_path):
            return False
            
        # Check file extension
        if not any(file_path.endswith(ext) for ext in self.whitelist['extensions']):
            return False
            
        # Skip files modified too frequently (rate limiting)
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

        return True

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
        """Process monitoring using WMI (preferred method)"""
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
                        
            except Exception as e:
                logging.error(f"Failed to start WMI monitor: {str(e)}")
                # Fall back to API method if WMI fails
                self.start_api_process_monitor()

        threading.Thread(target=wmi_monitor, daemon=True, name="WMIProcessMonitor").start()

    def start_api_process_monitor(self):
        """Process monitoring using Windows API (fallback method)"""
        def api_monitor():
            interval = int(self.config.get('MONITORING', 'process_check_interval', fallback=5))
            logging.info("Windows API process monitor started")
            
            # Get initial process list
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
        """Analyze a process against known signatures"""
        try:
            proc_info = f"{name}|||{path if path else 'unknown'}".encode()
            matches = self.rules.match(data=proc_info)
            
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

    def analyze_file(self, file_path, action):
        """Analyze a file against known signatures"""
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
        """Move file to quarantine directory"""
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
        """Attempt to terminate a suspicious process"""
        try:
            os.kill(pid, 9)
            logging.warning(f"TERMINATED process with PID: {pid}")
        except Exception as e:
            logging.error(f"Failed to terminate process {pid}: {str(e)}")

    def start_periodic_scans(self):
        """Run periodic scans of critical areas"""
        def scan_job():
            interval = int(self.config.get('MONITORING', 'scan_interval', fallback=3600))
            while self.monitoring_active:
                logging.info("Starting periodic scan")
                self.scan_critical_files()
                time.sleep(interval)

        scan_thread = threading.Thread(target=scan_job, daemon=True, name="PeriodicScan")
        scan_thread.start()

    def scan_critical_files(self):
        """Scan critical system files"""
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
        """Get current monitoring status"""
        paths = self.config.get('PATHS', 'watch_paths', fallback="C:\\Windows\\System32;C:\\Windows\\SysWOW64").split(';')
        return {
            'monitoring': self.monitoring_active,
            'paths': '\n'.join(paths),
            'activities': self.suspicious_activities[-20:]  # Return last 20 activities
        }

# Create HIDS instance
hids = HIDS()

# API endpoints
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
    # Create directories if they don't exist
    os.makedirs('static', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Run the app
    app.run(host='0.0.0.0', port=5000)
