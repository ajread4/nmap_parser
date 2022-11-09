# Python script to parse NMAP scans
import argparse
import os
from bs4 import BeautifulSoup
import re

def main():
    """
    	Main function for nmap_parse
    """
    parser = argparse.ArgumentParser(
        description='nmap_parse - a capability to examine nmap scans')
    parser.add_argument('file' ,action='store',help='specify the input nmap scan (can be either normal, xml, or grepable)')
    args=parser.parse_args()
    determine_type(args.file)


"""
Determine the type of nmap file 
"""
def determine_type(input_file):
    if os.path.splitext(input_file)[1] == ".xml":
        ip_data,port_data=analyze_xml(input_file)
        ip_file(ip_data)
        port_file(port_data)
    elif os.path.splitext(input_file)[1] == ".gnmap":
        print("GNMAP file")
        ip_data, port_data =analyze_gnmap(input_file)
        ip_file(ip_data)
        port_file(port_data)
    elif os.path.splitext(input_file)[1] == ".nmap":
        print("NMAP file")
        ip_data, port_data =analyze_nmap(input_file)
        ip_file(ip_data)
        port_file(port_data)
    else:
        print("Improper input file")

"""
Analyze XML nmap file
"""
def analyze_xml(input_file):
    final_mapping={}
    port_mapping={}
    with open(input_file,'r') as f:
        xml_data=f.read()
    BS_data=BeautifulSoup(xml_data,"xml")
    for ip in BS_data.find_all('host'):
        getIP=ip.find('address').get("addr")
        if ip.find('ports').find('port') != None:
            ip_list=[]
            for ip_ports in ip.find_all('ports'):
                for p in ip_ports.find_all('port'):
                    ip_list.append(p.get("portid"))
                    if p.get("portid") in port_mapping.keys():
                        oldvalues=port_mapping.get(p.get("portid"))
                        oldvalues.append(getIP)
                        port_mapping[p.get("portid")] = oldvalues
                    else:
                        port_mapping[p.get("portid")] = [getIP]
            final_mapping[getIP]=ip_list
        else:
            print(f'No ports open for ' + getIP)
    return final_mapping,port_mapping
"""
Analyze GNMAP nmap file
"""
def analyze_gnmap(input_file):
    final_mapping={}
    port_mapping={}
    with open(input_file,'r') as f:
        gnmap_data=f.readlines()
    for line in gnmap_data:
        final_port_list = []
        if "Ports:" in line:
            host=str(line).split("()")[0].split("Host: ")[-1].strip()
            open_list=re.findall("[0-9]+/open",line)
            for port in open_list:
                final_port_list.append(str(port).split("/open")[0])
                if port.split("/open")[0] in port_mapping.keys():
                    oldvalues=port_mapping.get(port.split("/open")[0])
                    oldvalues.append(host)
                    port_mapping[port.split("/open")[0]] = oldvalues
                else:
                    port_mapping[port.split("/open")[0]]=[host]
            final_mapping[host]=final_port_list
    return final_mapping,port_mapping

"""
Analyze NMAP nmap file
"""
def analyze_nmap(input_file):
    final_mapping={}
    port_mapping={}
    with open(input_file,'r') as f:
        nmap_data=f.readlines()
    for line in nmap_data:
        if "Nmap scan report for " in line:
            host=str(line).split(" ")[-1].replace("\n","")
            final_mapping[host]=[]
            final_port_list=[]
        if re.match("[0-9]+/tcp",line) or re.match("[0-9]+/udp",line):
            port=str(line.split("/")[0])
            if host in final_mapping.keys():
                old_values=final_mapping.get(host)
                old_values.append(port)
                final_mapping[host]=old_values
            else:
                final_mapping[host]=[port]
            if port in port_mapping.keys():
                old_values_port=port_mapping.get(port)
                old_values_port.append(host)
                port_mapping[port]=old_values_port
            else:
                port_mapping[port]=[host]
    return final_mapping,port_mapping

"""
Write to a text file for each port with IP:PORT combination
"""
def port_file(port_ip_file):
    for k,v in port_ip_file.items():
        with open(str(k) + "_open.txt", 'w') as f:
            for ips in v:
                f.write(ips + ":" + str(k) + "\n")

"""
Write to a text file for each IP listing each open port on a single line
"""
def ip_file(ip_port_file):
    for k,v in ip_port_file.items():
        with open(str(k) + "_open.txt", 'w') as f:
            for ports in v:
                f.write(ports+"\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(repr(err))