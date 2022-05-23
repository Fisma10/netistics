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
    if nslookup_output.find("Name:    ") != -1:
        domain_local = nslookup_output[nslookup_output.find("Name:    ") + 9: nslookup_output.find("\n", nslookup_output.find("Name:    ")) -1]
    else:
        domain_local = ""

    if is_private_ip(ip):  # Don't bother sending requests if it is a private IP
        print("\t-----")
        print("\t#LAN connection#")
        print("\tDomain: " + domain_local)
        print("\t-----\n")
        return

    # Request the data from the API
    ip_request_url = "http://ip-api.com/line/" + ip + "?fields=661049"
    ip_request = requests.get(ip_request_url)

    # http://ip-api.com/'s free limit is 45 requests per minute, so make sure it doesn't send too many requests
    if int(ip_request.headers['X-Rl']) <= 3:  # In practice it sometimes goes out of order, so this is to be safe
        print("\t - Waiting " + ip_request.headers['X-Ttl'] + " seconds for ip-api.com - ")
        time.sleep(int(ip_request.headers['X-Ttl']))

    # Format the data and print
    ip_info = ip_request.text.split("\n")
    if "".join(ip_info) == "":  # Catch all if the API doesn't respond with anything
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
    if ip_info[5] == ip_info[6]:  # If the ISP and Org are the same. Don't bother printing both
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
Takes a small part of www.file.net's information about the process
(Doesn't have an API so some removal of HTML tags is needed)
"""
def get_process_info(process):
    # Requests the file info from www.file.net
    file_dot_net_string = "https://www.file.net/process/" + process + ".html"  # The URL referring to the file
    file_dot_net = requests.get(file_dot_net_string)
    found = False

    # If not found, try using small case
    if file_dot_net.status_code == 200:
        found = True
    elif file_dot_net.status_code == 404:
        file_dot_net_string = file_dot_net_string.lower()
        file_dot_net = requests.get(file_dot_net_string)
        if file_dot_net.status_code == 200:
            found = True

    if found:

        # Since there is no API this whole section is trying to find some description about it while not grabbing the
        # HTML tags, also only use up to 200 characters so not to flood the screen
        proc_info_start = file_dot_net.text.find("The process known as")
        used_char_count = 0
        char_count = 0
        proc_info = ""
        in_bracket = False
        while used_char_count <= 200:
            if file_dot_net.text[proc_info_start + char_count] == "<":
                in_bracket = True
            elif file_dot_net.text[proc_info_start + char_count] == ">":
                in_bracket = False
            elif file_dot_net.text[proc_info_start + char_count] == "\n":
                break
            elif in_bracket == False:
                proc_info = proc_info + file_dot_net.text[proc_info_start + char_count]
                used_char_count = used_char_count + 1
            char_count = char_count + 1

        proc_info = proc_info + "..."
        print("-----")
        print(proc_info)
        print("(" + file_dot_net_string + ")")
        print("-----")
    time.sleep(1)  # Used to not overwhelm www.file.net

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

# Perform the netstat command and split it's output and create vars
netstat = subprocess.Popen("netstat -nbqo", stdout=subprocess.PIPE, shell=True)
netstat_output = (netstat.communicate())[0].decode()
netstat_output_list = (netstat_output.split("\n"))[4:]
connections = {}
temp_connections = ""
prev_output_ip = False  # Used to stop the printing of a service from an ignored connection

# If netstat didn't output anything. Most likely it was due to bad permissions, as stderr doesn't show anything when piped
if netstat_output_list == []:
    print(" - Netstat failed. Most likely due to not running as admin. To see output please run as admin - \n")

"""
Properly format and assign the connections to the executables
"""
for i in netstat_output_list:
    entry = i.split()
    if len(entry) < 1:
        continue

    if entry[0][0] != "[" and len(entry) > 2 and entry[0] != "Can":  # If it's a connection

        protocol = entry[0]  # The first part is the protocol. If you couldn't tell

        # Checking the local or unspecified addresses
        if entry[1][0] == "[":  # If IPv6
            port = entry[1][entry[1].find("]:") + 2:]
            if entry[1][:entry[1].find("]:") + 1] == "[::]":  # If it's an unspecified IP
                protocol = protocol + " UNSPECIFIED"
                if ignore_unspecified:
                    continue
            if entry[1][:entry[1].find("]:") + 1] == "[::1]":  # If it's an unspecified IP
                if ignore_local:
                    continue
        else:
            port = entry[1][entry[1].find(":") + 1:]
            if entry[1][:entry[1].find(":")] == "0.0.0.0":  # If it's an unspecified IP
                protocol = protocol + " UNSPECIFIED"
                if ignore_unspecified:
                    continue
            if entry[1][:4] == "127.":  # If it's an unspecified IP
                if ignore_local:
                    continue

        # Checking the foreign address
        if entry[2][:4] == "127.":  # If it's a local connection
            connection = "LOCALHOST" + entry[2][entry[2].find(":"):]
            if ignore_local:
                continue
        elif entry[2][0:entry[2].find("]:") + 1] == "[::1]":  # If it's a IPv6 local connection
            connection = "[LOCALHOST]" + entry[2][entry[2].find("]:") + 1:]
            if ignore_local:
                continue
        elif entry[2] == "*:*" or entry[2] == "0.0.0.0:0" or entry[2] == "[::]:0":  # If it's an unspecified connection
            connection = "NO_CONNECTION:0"
        else:
            connection = entry[2]

        # Checking for PID and Status if it exists
        if entry[3].isnumeric():
            status = ""
            PID = " - PID: " + entry[3]
        else:
            status = " - Status: " + entry[3]
            PID = " - PID: " + entry[4]

        # Put the data together and add it to the entry
        new_entry = protocol + " Port " + port + " to: " + connection + status + PID
        temp_connections = temp_connections + new_entry + "\n"
        prev_output_ip = True

    elif entry[0][0] == "[":  # If it's a executable

        try:  # Check if the executable entry is in the dictionary, if not then create the entry
            connections[entry[0]] = connections[entry[0]] + temp_connections
        except:
            connections[entry[0]] = temp_connections
        temp_connections = ""
        prev_output_ip = False
    elif entry[0] == "Can" and entry[1] == "not" and entry[2] == "obtain" and entry[3] == "ownership" and entry[4] == "information":  # If it's an unknown application
        try:  # Check if the executable entry is in the dictionary, if not then create the entry
            connections["[UNKNOWN-PROCESS]"] = connections["[UNKNOWN-PROCESS]"] + temp_connections
        except:
            connections["[UNKNOWN-PROCESS]"] = temp_connections
        temp_connections = ""
        prev_output_ip = False
    else:  # If it's a running service
        if prev_output_ip:
            temp_connections = temp_connections + "Using service: " + entry[0] + "\n"
        prev_output_ip = False

# Setting up vars for comparing IP addresses
prev_connection_ip = ""
current_connection_ip = ""

"""
Loop through all the formatted connections and call the get_ip_info function ONLY IF NOT a local connection and the previous
IP entry was the same (Thus saving on API calls)
"""
for i in connections:

    first_entry = True

    temp_connections_array = (connections[i][:-2]).split("\n")  # Split up all the connections under the exe file

    if temp_connections_array == ['']:
        continue

    print(i)  # Print the exe file

    get_process_info(i[1:-1])

    # Sets the previous connection variable to the first connection before the loop. Also determines if it's IPv4 or 6
    """
    if temp_connections_array[0].find("]:") == -1:
        prev_connection_ip = temp_connections_array[0][temp_connections_array[0].find("to: ") + 4: temp_connections_array[0].find(":", temp_connections_array[0].find("to: ") + 4)]
    else:
        prev_connection_ip = temp_connections_array[0][temp_connections_array[0].find("to: ") + 4: temp_connections_array[0].find("]:") + 1]
    """

    for j in temp_connections_array:  # Loops through all the connections under the exe

        # Determines if this line is referring to an IP address (And what version), or service
        if j.find("to: ") != -1:
            if j.find("]:") == -1:
                current_connection_ip = j[j.find("to: ") + 4 : j.find(":", j.find("to: ") + 4)]
            else:
                current_connection_ip = j[j.find("to: ") + 4 : j.find("]:") + 1]
            if first_entry:
                prev_connection_ip = current_connection_ip
                first_entry = False
        else:  # if j.find("service: ") != -1:
            print("\t" + j)
            continue

        # Checks if the connection is local, unspecified or the same IP as the previous connection. If not, then call get_ip_info
        if current_connection_ip == prev_connection_ip or prev_connection_ip == "LOCALHOST" or prev_connection_ip == "[LOCALHOST]" or prev_connection_ip == "NO_CONNECTION":
            prev_connection_ip = current_connection_ip
            print("\t" + j)
            continue
        else:
            if prev_connection_ip[0] == "[":  # Formats the IP to work with the API
                get_ip_info(prev_connection_ip[1:-1])
            else:
                get_ip_info(prev_connection_ip)
            prev_connection_ip = current_connection_ip
            print("\t" + j)
            continue
    # If the last IP isn't local or unspecified, then call get_ip_info (Last IP is only compared in the loop)
    if current_connection_ip != "LOCALHOST" and current_connection_ip != "[LOCALHOST]" and current_connection_ip != "NO_CONNECTION":
        if current_connection_ip[0] == "[":
            get_ip_info(current_connection_ip[1:-1])
        else:
            get_ip_info(current_connection_ip)
    print("")

"""

Checking hosts file

"""

print("######################")
print("- hosts file entries -")
print("######################")
print("")

hosts_file = open("C:\Windows\System32\drivers\etc\hosts", "r")  # Hosts file location

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
        else:  # If none of the above, get ip info
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

# List of startup locations in the Windows registry
startup_locations = ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                     "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                     "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"]

# Loop through each registry for the startup application keys
for i in startup_locations:
    print("# Entries located in: " + i + " #\n")

    # use the "reg query" command to get the keys and then split them
    cmd = "reg query " + i
    reg = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    reg_output = (reg.communicate())[0].decode()
    reg_output_list = reg_output.split("\r\n")

    for j in reg_output_list[2:-2]:  # Each key minus some extra unneeded text
        segments = j.split("    ")[1:]
        print(" - " + segments[0] + " - \n")
        print("Executable location: " + segments[2])
        get_process_info(segments[2][segments[2].rfind("\\") + 1:segments[2].find(".exe") + 4]) # Find the exe file
        print("")

startup_folders = [os.environ['USERPROFILE'] + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"]  # Specific folders in the file system for startup
for i in startup_folders:
    print("# Files inside: " + i + " #\n")

    # Checking each file in the folder
    for j in os.listdir(i):
        print(j)
        get_process_info(j)

if pause_on_finish:
    input("\nFinished!")
