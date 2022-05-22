import subprocess
import os
import time
import sys

try:
    import requests
except ImportError:
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests'])
    except:
        print("You must install pip")
        exit(1)
    try:
        import requests
    except:
        print("If not already installed by this script. Please install the 'request' library. Otherwise just re-run")
        exit(1)

# User cli argument flag defaults
ignore_local = True
ignore_unspecified = True
pause_on_finish = True

# Look for arguments passed
for i in sys.argv:
    if i[0] == "-":
        for j in i:
            if j == "c":
                pause_on_finish = False
            elif j == "l":
                ignore_local = False
            elif j == "u":
                ignore_unspecified = False
            elif j == "h":
                print("------")
                print(" Help ")
                print("------\n")
                print("Args:")
                print("-c : Don't pause on finish")
                print("-l : Include localhost connections in output")
                print("-u : Include unspecified local ip connections")
                exit(0)

# --- FUNCTIONS --- #

"""
Gets information about the IP address from http://ip-api.com's API
"""

def get_ip_info(ip):

    # Perform a nslookup on the IP address to find a potential domain, if not found return with a "N/A"
    nslookup = subprocess.Popen(("nslookup " + ip), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    nslookup_output = (nslookup.communicate())[0].decode()
    if nslookup_output.find("name = ") != -1:
        domain_local = nslookup_output[nslookup_output.find("name = ") + 7: nslookup_output.find("\n", nslookup_output.find("name = ")) - 1]
    else:
        domain_local = ""

    if is_private_ip(ip): # Don't bother sending requests if it is a private IP
        print("\t-----")
        print("\t#LAN connection#")
        print("\tDomain: " + domain_local)
        print("\t-----\n")
        return

    # Request the data from the API
    ip_request_url = "http://ip-api.com/line/" + ip + "?fields=661049"
    ip_request = requests.get(ip_request_url)

    # http://ip-api.com/'s free limit is 45 requests per minute, so make sure it doesn't send too many requests
    if int(ip_request.headers['X-Rl']) < 5: # In practice it sometimes goes out of order, so this is to be safe
        print("\t - Waiting " + ip_request.headers['X-Ttl'] + " seconds for ip-api.com - ")
        time.sleep(int(ip_request.headers['X-Ttl']))

    # Format the data and print
    ip_info = ip_request.text.split("\n")
    if "".join(ip_info) == "": # Catch all if the API doesn't respond with anything
        print("\t-----")
        print("\t#IP Info not found#")
        print("\t-----\n")
        return
    print("\t-----")
    if domain_local != ip_info[7]:
        print("\t# DOMAIN CONFLICT! #")
        print("\tYour DNS says: " + domain_local)
        print("\tIP-API DNS says: " + ip_info[7])
    else:
        print("\tDomain: " + domain_local)
    if ip_info[5] == ip_info[6]: # If the ISP and Org are the same. Don't bother printing both
        print("\tOrganization: " + ip_info[6])
    else:
        print("\tInternet Service Provider (ISP): " + ip_info[5])
        print("\tOrganization: " + ip_info[6])
    print("\tProxy, VPN or TOR?: " + ip_info[8])
    print("\tCountry: " + ip_info[0])
    print("\tRegion: " + ip_info[1])
    print("\tCity: " + ip_info[2])
    if ip_info[3] != "":
        print("\tDistrict: " + ip_info[3])
    if ip_info[4] != "":
        print("\tZip: " + ip_info[4])
    print("\t-----\n")

"""
Uses linux's "file" command to get some more info
"""

def get_file_info(file):
    # Finds the file path for the process, if not already found
    file_path = ""
    if "/" not in file:
        which_cmd = "which " + file
        file_path = subprocess.Popen(which_cmd, stdout=subprocess.PIPE, shell=True).communicate()[0].decode()[:-1]
        if file_path == "":
            find_cmd = "find / -name " + file + " 2>/dev/null"
            if os.getuid() != 0:
                print("# Not root, so missing parts of the file system #")
            file_path = file_path + subprocess.Popen(find_cmd, stdout=subprocess.PIPE, stderr=None, shell=True).communicate()[0].decode()[:-1]
            if "\n" in file_path:
                file_path = file_path[:file_path.find("\n")]
            elif file_path == "":
                return
    else:
        file_path = file

    # Uses the full file path for the process to get the file info
    file_cmd = "file " + file_path
    file_info = subprocess.Popen(file_cmd, stdout=subprocess.PIPE, shell=True).communicate()[0].decode()[:-1]

    # Prints file info
    print("-----")
    print(file_path)
    print(file_info[len(file_path)+1:])
    print("-----")

def get_process_info(process):

    # Uses apt show to find information from the package manager. Makes sure if it's a desktop file, try without the extension
    if process[-8:] == ".desktop":
        cmd = "apt show " + process[:-8] + " 2>/dev/null"
    else:
        cmd = "apt show " + process + " 2>/dev/null"
    apt_show = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    apt_show_text = (apt_show.communicate())[0].decode()
    start = apt_show_text.find("Description: ")
    if start == -1:
        get_file_info(process)
        return
    proc_info = apt_show_text[apt_show_text.find("Description: ") + 13 : apt_show_text.find("\n\n")]

    if len(proc_info) > 300:
        proc_info = proc_info[:300] + "..."
    print("-----")
    print(proc_info)
    print("-----")

"""
Checks if an IP address is private
"""

def is_private_ip(ip):
    if ip[0:3] == "10.":
        return True
    elif len(ip) > 8:
        if ip[0:8] == "192.168.":
            return True
        if ip[0:4] == "172.":
            if ip[4:6].isnumeric() and ip[6] == ".":
                if int(ip[4:6]) >= 16 and int(ip[4:6]) <= 31:
                    return True
    return False

# --- END FUNCTIONS --- #

"""

Checking current connections via netstat

"""

print("")
print("###############################")
print("- Current network connections -")
print("###############################")
print("")

# Perform the netstat command
netstat = subprocess.Popen("netstat -apneW", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

# Check if netstat is actually installed, if not then try to, and if that fails then print the message and continue
netstderr = netstat.stderr.read().decode()
if "netstat: not found" in netstderr:  # Shell response when not there
    if os.getuid() == 0:  # If root
        print("# Installing netstat... #")
        install_netstat = subprocess.Popen("apt install net-tools -y", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)  # Install netstat
        install_netstat.communicate()  # Wait for install to finish
        print("# Installed! #\n")
        netstat = subprocess.Popen("netstat -apneW", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    else:
        print("# netstat is not installed. Please run as root or install 'net-tools' #\n")

if "root" in netstderr:
    print(netstderr)

netstat_output = (netstat.communicate())[0].decode()
netstat_output_list = (netstat_output.split("\n"))[2:]
connections = {}

for i in netstat_output_list:
    entry = i.split()
    if len(entry) < 1:
        continue
    if i == "Active UNIX domain sockets (servers and established)":  # Not interested in the Active UNIX domain sockets as they are local
        break

    # Split the output into the corresponding vars
    protocol = entry[0]
    port = entry[3][entry[3].rfind(":") + 1:]
    local_address = entry[3]
    if local_address[:4] == "127." or local_address[:local_address.rfind(":")] == "::1" and ignore_local:
        continue
    elif local_address[:local_address.rfind(":")] == "0.0.0.0" or local_address[:local_address.rfind(":")] == "::" and ignore_unspecified:
        continue
    connection = entry[4]
    if connection[:4] == "127." or connection[:connection.rfind(":")] == "::1":
        connection = "LOCALHOST" + connection[connection.rfind(":"):]
    elif connection[:connection.rfind(":")] == "0.0.0.0" or connection[:connection.rfind(":")] == "::":
        connection = "NO_CONNECTION:0"
    status = entry[5]
    if protocol[0:3] != "raw" and status.isnumeric():  # RAW packets status is formatted differently
        status = "N/A"
        pid = entry[7][:entry[7].find("/")]
        program = entry[7][entry[7].find("/") + 1:] + "".join(entry[8:])
    else:
        pid = entry[8][:entry[8].find("/")]
        program = entry[8][entry[8].find("/") + 1:] + "".join(entry[9:])
    entry_string = protocol + " Port " + port + " to: " + connection + " - Status: " + status + " - PID: " + pid + "\n"

    # Add the program to the connections dictionary. Append if already exists
    try:
        connections[program] = connections[program] + entry_string
    except:
        connections[program] = entry_string

# Print the connections related to the programs
for i in connections:
    print("[" + i + "]")
    if i != "-":
        get_process_info(i)
    connections_array = connections[i].split("\n")
    for j in connections_array[:-1]:
        print("\t" + j)
        if "LOCALHOST" not in j and "NO_CONNECTION:0" not in j:
            get_ip_info(j[j.find("to: ") + 4 : j.rfind(":", 0, j.find("- Status: "))])
        else:
            print("")

"""

Checking hosts file

"""

print("######################")
print("- hosts file entries -")
print("######################")
print("")

hosts_file = open("/etc/hosts", "r")  # Hosts file location

"""
Checks each line if it's a proper entry
"""
for entry in hosts_file:
    if ord(entry[0]) > 127:  # The first entry can sometimes have weird characters, so ignore if so
        continue
    if entry[0] != "#":  # '#' Means it's a comment
        segments = entry.split()
        if segments == []:
            continue
        print(" ".join(segments[1:]) + " -> " + segments[0], end="")
        if is_private_ip(segments[0]):  # Checks if a connection made on the local network
            print(" (LAN Connection)")
        elif segments[0][:4] == "127." or segments[0] == "::1":  # Checks if it is a loopback
            print(" (LOCALHOST)")
        else: # If none of the above, get ip info
            print("")
            get_ip_info(segments[0])

"""

Checking startup applications

"""

print("")
print("#################")
print("- Startup files -")
print("#################")
print("")

# Check the startup folders for files
startup_folders = ["/etc/init.d/", "/etc/xdg/autostart/", os.environ['HOME'] + "/.config/autostart/"]
for i in startup_folders:
    print("# Files inside: " + i + " #\n")
    try:
        for j in os.listdir(i):
            print(" - " + j + " - ")
            get_process_info(j)
            print("")
    except FileNotFoundError:
        print(" #DOESN'T EXIST# ")

# Check /etc/ for RC startup files
print("\n# RC files: #\n")
for i in os.listdir("/etc/"):
    if i[:2] == "rc" and i[-2:] == ".d":
        print(" - " + i + " - ")
        print("Links:")
        for j in os.listdir("/etc/" + i + "/"):
            file_cmd = "file " + "/etc/" + i + "/" + j
            print(subprocess.Popen(file_cmd, stdout=subprocess.PIPE, shell=True).communicate()[0].decode()[:-1])
        print("")

# Find all "autostart" files in the file system and display
print("\n# 'Autostart' files: #\n")
autostart_files = subprocess.Popen('find / -name "*autostart*" 2>/dev/null', stdout=subprocess.PIPE, shell=True)
autostart_files_output = (autostart_files.communicate())[0].decode()
autostart_files_output_list = (autostart_files_output.split("\n"))
if os.getuid() != 0:
    print("# Not root, so missing parts of the file system #\n")
for i in autostart_files_output_list[:-1]:
    # Similar to get_process_info, but slightly different output wanted
    get_file_info(i)
    print("")

print("# .bashrc file #\n")
print("- Lines in .bashrc after 117 -")
bashrc_location = os.environ['HOME'] + "/.bashrc"
bashrc = open(bashrc_location, "r")
bashrc_text = bashrc.readlines()
for line in bashrc_text[117:]:
    print(line)

if pause_on_finish:
    input("\nFinished!")
