import nmap

scanner = nmap.PortScanner()

print("Welcome. This is a simple nmap automation tool")
print("<----------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan: \n")
print(f"The IP address you entered is: {ip_addr}")
type(ip_addr)

resp = input(
    """
    \nPlease enter the type of scan you want to run
    1) SYN ACK Scan
    2) UDP Scan
    3) Comprehensive Scan
    """
)
print(f"You have selected option: {resp}")

if resp == '1':
    print(f"Nmap Version: {scanner.nmap_version()}")
    scan_info = scanner.scan(ip_addr, '1-1024', '-v -sS')
    # print(scan_info)
    print(scanner.scaninfo())
    print(f"IP status: {scanner[ip_addr].state()}")
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr].get('tcp', 'No TCP ports open').keys())
elif resp == '2':
    print(f"Nmap Version: {scanner.nmap_version()}")
    scan_info = scanner.scan(ip_addr, '1-1024', '-v -sU')
    # print(scan_info)
    print(scanner.scaninfo())
    print(f"IP status: {scanner[ip_addr].state()}")
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr].get('udp', 'No UDP ports open').keys())
elif resp == '3':
    print(f"Nmap Version: {scanner.nmap_version()}")
    scan_info = scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    # print(scan_info)
    print(scanner.scaninfo())
    print(f"IP status: {scanner[ip_addr].state()}")
    print(scanner[ip_addr].all_protocols())
    print("Open ports: ", scanner[ip_addr].get('tcp', 'No TCP ports open').keys())
elif resp not in ['1', '2', '3']:
    print('Please enter a valid option.')