# Log Analyser

A Python tool that analyses server log files to detect suspicious activity 
including failed login attempts and potential brute force attacks.

## Features
- Extracts all failed login attempts with associated IP and username
- Extracts all IP addresses from the log
- Extracts all timestamps
- Extracts error codes (404, 500 etc)
- Counts failed login attempts per IP address
- Flags IPs with more than 3 failed attempts as potential brute force attacks
- Exports all findings to a text file

## How to Use
1. Add your log file and name it `server.log`
2. Run the script:
```bash
python3 LogAnalyzer.py
```
3. Results are printed to terminal and exported to `LogAnalysis.txt`

## Example Output
Failed Logins per IP:
192.168.1.105: 4
10.0.0.45: 3
85.250.54.29: 5

Possible Brute Force Attempts:
192.168.1.105: 4
85.250.54.29: 5

## Built With
- Python 3
- re (built-in)
