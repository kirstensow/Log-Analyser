import re
import os


#Extractions with regex

#Failed Logins
def failed (contents):
    failed_login = re.compile(r'.*Failed login attempt from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user: (\w+)')
    failed_match = failed_login.findall(contents)
    print ('Failed Login Attempts: ', failed_match)
    return failed_match

#IP Addresses
def ip(contents):
    ip_addr = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ip_match = ip_addr.findall(contents)
    print('IP Addresses: ', ip_match)
    return ip_match

#Timestamps
def time(contents):
    timestamp = re.compile(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}')
    time_match = timestamp.findall(contents)
    print ('Timestamps: ' ,time_match)
    return time_match

#Error codes
def error(contents):
    error_code = re.compile(r'Error \d{3}')
    error_match = error_code.findall(contents)
    print('Error codes: ', error_match)
    return error_match

#Analysis
def analysis(failed_match):
    ip_counts = {}
    for failure in failed_match:
        ip = failure[0]
        if ip in ip_counts:  # if the ip is already in the dictionary increase the count by one and if not, assign it a value of 1
            ip_counts[ip] += 1
        else:
            ip_counts[ip] = 1
    print('Failed Logins per IP: ' , ip_counts)
    brute_force = {}

    for ipaddress, counts in ip_counts.items():

        if counts > 3:
            brute_force[ipaddress] = counts

    print('Possible Brute Force Attempts!: ', brute_force)

    return ip_counts, brute_force


def export (failed_match, ip_match, ip_counts, brute_force, time_match, error_match):
    with open('LogAnalysis.txt', 'w') as file:

        file.write('\nFailed Login Attempts:\n')
        for fails in failed_match:
          file.write(str(fails))
          file.write('\n')


        file.write('\nIP Addresses:\n')
        for items in ip_match:
            file.write(str(items))
            file.write('\n')


        file.write('\nTimestamps:\n')
        for items in time_match:
            file.write(str(items))
            file.write('\n')


        file.write('\nError Codes:\n')
        for codes in error_match:
            file.write(str(codes))
            file.write('\n')

        file.write('\nFailed Logins per IP:\n')
        for ip, count in ip_counts.items():
            file.write(f'{ip}: {count}\n')

        file.write('\nPossible Brute Force Attempts:\n')
        for ip, count in brute_force.items():
            file.write(f'{ip}: {count}\n')



# Walk through current directory and find all .log files
for foldername, subfolders, filenames in os.walk(os.getcwd()):
    for filename in filenames:
        if filename.endswith('.log'):  # only process .log files
            # join folder path and filename to get full file path to open it
            with open(os.path.join(foldername, filename), 'r') as file:
                contents = file.read()
            failed_match = failed(contents)
            ip_match = ip(contents)
            time_match = time(contents)
            error_match = error(contents)
            ip_counts, brute_force = analysis(failed_match)
            export(failed_match, ip_match, ip_counts, brute_force, time_match, error_match)
