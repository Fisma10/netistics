from elevate import elevate
import subprocess

elevate()

netstat = subprocess.Popen("netstat -b -n", stdout=subprocess.PIPE, shell=True)
netstat_output = (netstat.communicate())[0].decode()
netstat_output_list = (netstat_output.split("\n"))[4:]
connections = {}
temp_connections = ""
for i in netstat_output_list:
    entry = i.split()
    if len(entry) < 1:
        continue
    if entry[0][0] != "[" and len(entry) > 2:

        protocol = entry[0]

        if entry[1][0] == "[":
            port = entry[1][entry[1].find("]:") + 2:]
        else:
            port = entry[1][entry[1].find(":") + 1:]

        if entry[2][0:entry[2].find(":")] == "127.0.0.1":
            connection = "LOCAL" + entry[2][entry[2].find(":"):]
        else:
            connection = entry[2]

        new_entry = protocol + " Port " + port + " to: " + connection
        temp_connections = temp_connections + new_entry + "\n"
    elif entry[0][0] == "[":
        try:
            connections[entry[0]] = connections[entry[0]] + temp_connections
        except:
            connections[entry[0]] = temp_connections
        temp_connections = ""
    else:
        temp_connections = temp_connections + "Using service: " + entry[0] + "\n"
for i in connections:
    print(i)
    print(connections[i])

"""
[First Commit]
Completed Tasks:
*Asks for elevated privs (Using elevate python lib)
*Gets output from netstat and puts it in variables
*Processes string output and combines them with running programs
"""