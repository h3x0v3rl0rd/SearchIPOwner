import requests
import json
import sys
import os
import time
import argparse

VERSION = "1.2"

# Query ARIN API for IP details
def query_arin_ip(ip):
    url = f"https://whois.arin.net/rest/ip/{ip}"
    headers = {"Accept": "application/json"}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.RequestException as e:
        print(f"[-] ARIN API request failed for {ip}: {e}")
        return None

# Extract organization name from the ARIN response data
def get_org(data):
    if "orgRef" in data["net"]:
        return data["net"]["orgRef"]["@name"]
    elif "customerRef" in data["net"]:
        return data["net"]["customerRef"]["@name"]
    return "null"

# Query ipinfo.io API for more details like geolocation, ASN, etc.
def query_ipinfo(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()  # Returns a JSON object with detailed IP info
    except requests.RequestException as e:
        print(f"[-] Failed to query ipinfo.io for {ip}: {e}")
        return None

# Query ip-api.com for more detailed geolocation, ASN, etc.
def query_ip_api(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()  # Returns a JSON object with detailed IP info
    except requests.RequestException as e:
        print(f"[-] Failed to query ip-api.com for {ip}: {e}")
        return None

# Scan a single IP and extract details
def scan_single_ip(ip):
    data = query_arin_ip(ip)
    ip_info = query_ipinfo(ip)  # Get additional info from ipinfo.io
    ip_api = query_ip_api(ip)   # Get additional info from ip-api.com

    if data:
        try:
            name = get_org(data)
            net_block = data["net"]["netBlocks"]["netBlock"]
            ip_start = net_block["startAddress"]["$"]
            cidr_length = net_block["cidrLength"]["$"]
            ip_range = f"{ip_start}/{cidr_length}"

            # Get more details from ipinfo.io API
            city = ip_info.get("city", "null") if ip_info else "null"
            country = ip_info.get("country", "null") if ip_info else "null"
            org = ip_info.get("org", "null") if ip_info else "null"

            # Get more details from ip-api.com API
            isp = ip_api.get("isp", "null") if ip_api else "null"
            asn = ip_api.get("as", "null") if ip_api else "null"

            # Print detailed output
            print(f"[+] {ip}")
            print(f" |_ {name}")
            print(f" |_ {city}, {country}")
            print(f" |_ Org: {org}")
            print(f" |_ ISP: {isp}")
            print(f" |_ ASN: {asn}")
            print(f" _ {ip_range}\n")
            
            return f"{ip},{ip_range},{name},{city},{country},{org},{isp},{asn}\n"
        except KeyError as e:
            print(f"[-] Error extracting data for {ip}: {e}")
            return f"{ip},null,null,null,null,null,null,null\n"
    else:
        print(f"[+] {ip}")
        print(" |_ No Result\n")
        return f"{ip},null,null,null,null,null,null,null\n"

# Main logic to handle arguments and file processing
def main():
    print(f"Search IP Owner v{VERSION}\nn3rdh4x0r\n{'-' * 57}\n")
    
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Search IP Owner")
    parser.add_argument("target", help="IP address or path to a file containing IPs")
    parser.add_argument("-csv", action="store_true", help="Save output to CSV file")
    args = parser.parse_args()
    
    save_csv = args.csv
    target = args.target
    output = ""

    # Check if the target is a file or a single IP
    if os.path.exists(target):
        if os.path.isfile(target):
            with open(target, "r") as file:
                for ip in file.readlines():
                    output += scan_single_ip(ip.strip())
        else:
            print(f"[-] {target} is a directory. Please provide a valid file path.")
            sys.exit(1)
    else:
        output += scan_single_ip(target)

    # If CSV output is requested, save to file
    if save_csv:
        path = f"{os.getcwd()}/output_{int(time.time())}.csv"
        with open(path, "w") as csv_file:
            csv_file.write(output)
        print(f"[+] Output saved to {path}")

if __name__ == "__main__":
    main()
