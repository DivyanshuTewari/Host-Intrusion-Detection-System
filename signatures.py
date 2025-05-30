signatures = """
rule malicious_script {
    meta:
        description = "Detects common malicious script patterns"
        severity = "high"
    strings:
        $s1 = "Invoke-Expression"
        $s2 = "DownloadString"
        $s3 = "FromBase64String"
        $s4 = "New-Object Net.WebClient"
        $s5 = "Start-Process -WindowStyle Hidden"
    condition:
        any of them and
        not (file.path contains "C:\\Windows\\System32")
}

rule suspicious_process_names {
    meta:
        description = "Detects processes with suspicious names"
        severity = "medium"
    strings:
        $s1 = "mimikatz"
        $s2 = "bloodhound"
        $s3 = "cobaltstrike"
    condition:
        any of them and
        not (file.path contains "C:\\Windows\\System32") and
        not (file.path contains "C:\\Program Files\\")
}

rule suspicious_powershell {
    meta:
        description = "Detects potentially dangerous PowerShell command usage"
        severity = "high"
    strings:
        $s1 = "Invoke-Expression"
        $s2 = "DownloadString"
        $s3 = "FromBase64String"
        $s4 = "New-Object Net.WebClient"
        $s5 = "Start-Process -WindowStyle Hidden"
    condition:
        any of them and
        file.extension == "ps1" and
        not (file.path contains "C:\\Windows\\System32")
}
"""