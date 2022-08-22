#!/usr/bin/python3
import subprocess as sp
from sys import argv
from datetime import datetime
from requests import get
import socket

## Get hosts via arguments or prompt ##
def get_hosts(): # Returns host dictionary
    ## Variables ## 
    hosts = {}
    http = '://'
    colon = ':'
    slash = '/'
    ## Get host argument ## 
    if len(argv) > 1:
        host_string = argv[1].lower().replace(' ','') 
    else: host_string = input("Enter IP address or ranges: ").lower().replace(' ','')
    ## Isolate scheme ## 
    if http in host_string: 
        http_index = host_string.find(http)
        hosts['scheme'] = host_string[:http_index+len(http)]
        host_string = host_string[http_index+len(http):]
    else:
        hosts['scheme'] = None
    #print(f"Isolate Scheme: Host_string = " + str(host_string) + ". Hosts['scheme'] = " + str(hosts['scheme']) + ".")
    ## Isolate path ##
    if slash in host_string:
        slash_index = host_string.find(slash)
        hosts['path'] = host_string[slash_index:]
        host_string = host_string[:slash_index]
    else:
        hosts['path'] = None
    #print(f"Isolate Path: Host_string = " + str(host_string) + ". Hosts['path'] = " + str(hosts['path']) + ".")
    ## Isolate Port ##
    if colon in host_string:
        colon_index = host_string.find(colon)
        hosts['port'] = host_string[colon_index+1:]
        host_string = host_string[:colon_index]
    else:
        hosts['port'] = None
    #print(f"Isolate Port: Host_string = " + str(host_string) + ". Hosts['port'] = " + str(hosts['port']) + ".")
    ## Isolate domain ##
    hosts['domain'] = host_string
    #print(f"Isolate domain: Host_string = " + str(host_string) + ". Hosts['domain'] = " + str(hosts['domain']) + ".")
    ## Return dictionary ## 
    return hosts

## Get ports via arguments or prompt ##
def get_ports(): # Returns list of ports
    if len(argv) > 2:
        ports = argv[2].lower().replace(' ','')
    else: ports = input('Enter ports e.g. "80,443": ').lower().replace(' ', '')
    ports = ports.split(",") 
    if host_dict['port'] != None and host_dict['port'] not in ports:
        ports.append(host_dict['port'])
    return ports

## Allow port to be app name as well as port number ##
# (item) is port or app name from user input. Will be vaiable 'ports'
def common_port_lookup(item):
    apps = {
    "http":"80,443",
    "https":"80,443",
    "ssh":"22",
    "dns":"53",
    "smb":"445",
    "ftp":"20,21",
    "smtp":"25",
    "imap":"143,993",
    "pop":"109,110,995",
    "snmp":"161,l62",
    "rdp":"3389",
    "vnc":"5800,5900",
    "ldap":"389"
    }
    if item in apps:
        return apps[item] # if user entered an app, returns the port value
    else:
        return item # if port # was entered it keeps it

## Run fuctions to define host and port variables ##
host_dict = get_hosts()
ports_list = get_ports()
hosts = host_dict['domain']
ports = ','.join(ports_list)

#print(f"hosts = " + str(hosts))
#print(f"ports = " + ports)

## Common port lookup ##
# Turns ports into an array and checks each. Then back to comma delimited string.
ports = ",".join(map(common_port_lookup,ports.split(",")))

## Getting user's internal and external IPs ##
def get_internal_ip(dest_ip):    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((dest_ip, 80))
    ip = (s.getsockname()[0])
    s.close()
    return ip

def get_external_ip(dest_ip):
    public_ip = get('https://api.ipify.org').text 
    return public_ip

## Running NMAP request ##
# Sets NMAP port flags, if ports exist
def nmap_run(ports):
    options = sp.run(['nmap', hosts, '-p', ports, '-Pn'], capture_output=True, text=True)
    if ports == '':
        options = sp.run(['nmap', hosts, '-Pn'], capture_output=True, text=True)
    return options

# Running NMAP and defining variables
print("Please wait while running scan ...")
result = nmap_run(ports) # Runs nmap and stores result
resultlist = result.stdout.split('\n') # Make nmap output a list
###### Placeholder to replace the below with local time using datetime.now() and https://stackoverflow.com/questions/13855111/how-can-i-convert-24-hour-time-to-12-hour-time
resultlist[0] = f"\nStarting {resultlist[0][resultlist[0].find('at'):]}" # Inject better starting text 

# Find destination IP in nmap string
def nmap_find_ip(string): # Gets the IP at the end of an nmap string
    dest_ip = string.split(' ')[-1].strip('()')
    return dest_ip

# Check if IP is private. Returns True if in RFC 1918
def private_ip_check(ip):
    octet = ip.split('.') # Turn IP into array of octets
    octet = list(map(int, octet)) # Turn octets into integers 
    if octet[0] == 10:
        return True
    elif octet[0] == 172 and (octet[1] > 15 or octet[1] < 32):
        return True
    elif octet[0] == 192 and octet[1] == 168:
        return True
    else: return False

# If private_ip_check True return int_ip. If False return ext_ip.
def int_or_ext_IP(ip):
    if private_ip_check(ip) == True:
        return get_internal_ip(ip)
    elif private_ip_check(ip) == False:
        return get_external_ip(ip)
    else: print("Error: IP was somehow not public or private")

# Insert IP into Nmap output
def nmap_inject_ips(list):
    start_msg = "Nmap scan report"
    outlist = [] 
    for line in list:
        if start_msg in line:
            dest_ip = nmap_find_ip(line)
            source_ip = int_or_ext_IP(dest_ip) 
            index = line.index("for") # Nmap scan report for <dest>
            my_from = "from: "
            #if int_ip == "VPN is not connected" and private_ip_check(dest_ip):
            #    my_from = "ERROR: "
            # Nmap scan report (from <source>) for <dest>
            ip_line = f"{line[:index]}({my_from}{source_ip}) {line[index:]}" 
            outlist.append(ip_line)
        else: outlist.append(line)
    return outlist # Return modified nmap output

# outlist is equal to the modified nmap output
outlist = nmap_inject_ips(resultlist)
print('\n'.join(outlist)) # Print list
