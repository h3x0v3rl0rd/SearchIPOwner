import urllib.request
import json
import sys
import os
import time

VERSION = "1.1"

def query_arin_ip(ip):
    url = f"https://whois.arin.net/rest/ip/{ip}"
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/json")
    
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode('utf-8'))
    except:
        print("[-] ARIN API failed to return proper data")
        return None

def get_org(data):
    if "orgRef" in data["net"]:
        return data["net"]["orgRef"]["@name"]
    if "customerRef" in data["net"]:
        return data["net"]["customerRef"]["@name"]
    return "null"

def scan_single_ip(ip):
    try:
        data = query_arin_ip(ip)
        name = get_org(data)
        net_block = data["net"]["netBlocks"]["netBlock"]
        ip_start = net_block["startAddress"]["$"]
        cidr_length = net_block["cidrLength"]["$"]
        ip_range = f"{ip_start}/{cidr_length}"
        
        print(f"[+] {ip}")
        print(f" |_ {name}")
        print(f" \_ {ip_range}\n")
        return f"{ip},{ip_range},{name}\n"
    except:
        print(f"[+] {ip}")
        print(" |_ No Result\n")
        return f"{ip},null,null\n"

if __name__ == "__main__":
    save_csv = False
    output = ""
    print(f"Search IP Owner v{VERSION}\nn3rdyn3xus\n{'-' * 57}\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} target [option]\n\n\tTarget\tIP address or path to a file that contains IPs\n\t-csv\tSave to a file in CSV format")
        sys.exit(0)

    target = sys.argv[1]

    if os.path.exists(target):
        if os.path.isfile(target):
            if "-csv" in sys.argv:
                save_csv = True
            for ip in open(target, "r").readlines():
                output += scan_single_ip(ip.strip())
        else:
            print(f"[-] {target} is a directory. Please provide a valid file path.")
    else:
        output += scan_single_ip(target)

    if save_csv:
        path = f"{os.getcwd()}/output_{int(time.time())}.csv"
        with open(path, "w+") as csv_file:
            csv_file.write(output)
        print(f"[+] Output saved to {path}")
