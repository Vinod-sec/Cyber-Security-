import nmap
import socket
from datetime import datetime

# Function to get current timestamp for file logging
def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Function to choose scan type
def scan_type_options():
    print("\nChoose scan type:")
    print("1. SYN Scan")
    print("2. Version Scan")
    print("3. OS Detection")
    print("4. Vulnerability Scan (NSE)")
    scan_choice = input("Enter 1, 2, 3, or 4: ")

    if scan_choice == "1":
        return '-sS'  # SYN Scan
    elif scan_choice == "2":
        return '-sV'  # Version Scan
    elif scan_choice == "3":
        return '-O'  # OS Detection
    elif scan_choice == "4":
        return '--script=vuln'  # Vulnerability Scan using Nmap Scripting Engine
    else:
        print("Invalid choice. Using default SYN Scan.")
        return '-sS'  # Default SYN Scan

# Function to get user input for ports to scan
def get_ports_to_scan():
    ports_input = input("Enter the ports to scan (single port, comma-separated, or range, e.g., 1-1024, 80,443): ")
    
    # Parsing and handling the input for ranges or individual ports
    port_list = []
    for part in ports_input.split(','):
        if '-' in part:  # Handling a range (e.g., 1-1024)
            start, end = map(int, part.split('-'))
            if start > 0 and end <= 65535:
                port_list.extend(range(start, end + 1))
            else:
                print(f"Invalid range {start}-{end}. Skipping this range.")
        else:  # Handling individual ports
            port_list.append(int(part.strip()))
    
    # Return a list of ports
    return list(set(port_list))  # Removing duplicates, if any.

# Function to get user input for custom IPs to scan
def get_target_ips():
    ips_input = input("Enter IPs to scan (comma-separated, e.g., 127.0.0.1,192.168.1.1): ")
    return [ip.strip() for ip in ips_input.split(',')]

# Initialize Nmap Port Scanner
nm = nmap.PortScanner()

# Ask for target IPs
target_ips = get_target_ips()  # Get target IPs from the user

# Ask for scan type
scan_type = scan_type_options()  # User chooses the scan type here

# Get user input for ports
ports_to_scan = get_ports_to_scan()  # User chooses the ports here

# Logging the scan results
log_file_name = f'scan_results_{get_timestamp().replace(" ", "_").replace(":", "-")}.txt'
with open(log_file_name, 'w') as log_file:
    log_file.write("==== Multi-Target Scan Log ====\n")
    log_file.write(f"Scan Time: {get_timestamp()}\n\n")
    
    # Iterate through each target IP
    for ip in target_ips:
        log_file.write(f"===== Scanning Target: {ip} =====\n")
        log_file.write(f"Host: {ip}\n")
        
        try:
            nm.scan(hosts=ip, arguments='-sn')  # Ping scan to check if host is up
            if ip in nm.all_hosts():
                log_file.write(f"Host {ip} is up.\n")
                
                # Perform scan on ports using selected scan type
                for port in ports_to_scan:
                    log_file.write(f"  Scanning Port: {port}...\n")
                    nm.scan(hosts=ip, arguments=f'-p {port} {scan_type}')  # Scan ports with selected scan type
                    
                    try:
                        # State and Service for each port
                        state = nm[ip]['tcp'][port]['state']
                        service = nm[ip]['tcp'][port]['name']
                        log_file.write(f"  Port: {port} | State: {state} | Service: {service}\n")
                        
                        # If 'OS Detection' or 'Vuln Scan' is selected, get additional info
                        if scan_type == '-O':
                            os_info = nm[ip].get('osmatch', "OS information not available")
                            log_file.write(f"  OS Info: {os_info}\n")
                        
                        if scan_type == '--script=vuln':
                            # Vulnerability scanning results
                            vuln_info = nm[ip].get('hostscript', [])
                            if vuln_info:
                                log_file.write("  Vulnerabilities Found:\n")
                                for vuln in vuln_info:
                                    log_file.write(f"    {vuln.get('output', 'No detailed vulnerability info')}\n")
                            else:
                                log_file.write("  No vulnerabilities found.\n")

                    except KeyError:
                        log_file.write(f"  Port {port} not found or closed.\n")
            else:
                log_file.write(f"Host {ip} is down.\n")
        except Exception as e:
            log_file.write(f"Error with host {ip}: {str(e)}\n")

    log_file.write("\n==== Scan Completed ====\n")
    log_file.write(f"Scan completed at: {get_timestamp()}\n")

print(f"Scan completed. Results saved in {log_file_name}")
