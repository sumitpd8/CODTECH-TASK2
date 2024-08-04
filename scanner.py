import nmap
import requests
from colorama import Fore, Style, init


nm = nmap.PortScanner()
init(autoreset=True)

# Function to scan a target for open ports
def scan_open_ports(target):
    print(f"\n{Fore.CYAN}Scanning {target} for open ports...")
    try:
        nm.scan(target, '1-1024')  # Scanning the first 1024 ports
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    if nm[host][proto][port]['state'] == 'open':
                        open_ports.append(port)
        return open_ports
    except Exception as e:
        print(f"{Fore.RED}Error scanning ports: {e}")
        return []

# Function to check for outdated software versions
def check_outdated_software(url):
    print(f"\n{Fore.CYAN}Checking {url} for outdated software versions...")
    try:
        response = requests.get(url)
        headers = response.headers
        print(f"{Fore.YELLOW}Response Headers: {headers}")
        server_header = headers.get('Server')
        if server_header:
            print(f"{Fore.GREEN}Server header: {server_header}")
            # To check if the server version is outdated
        else:
            print(f"{Fore.RED}No server header found.")
    except Exception as e:
        print(f"{Fore.RED}Error checking software versions: {e}")

# Function to detect common misconfigurations
def detect_misconfigurations(url):
    print(f"\n{Fore.CYAN}Checking {url} for common misconfigurations...")
    try:
        response = requests.get(url)
        headers = response.headers
        if 'X-Frame-Options' not in headers:
            print(f"{Fore.RED}Missing X-Frame-Options header. {Style.RESET_ALL}Possible Clickjacking attack vector.")
        if 'X-Content-Type-Options' not in headers:
            print(f"{Fore.RED}Missing X-Content-Type-Options header. {Style.RESET_ALL}Possible MIME-sniffing attack vector.")
        if 'Content-Security-Policy' not in headers:
            print(f"{Fore.RED}Missing Content-Security-Policy header. {Style.RESET_ALL}Possible XSS attack vector.")
    except Exception as e:
        print(f"{Fore.RED}Error detecting misconfigurations: {e}")

# Function to display possible cyber attacks
def display_possible_attacks():
    print(f"\n{Fore.CYAN}Possible cyber attacks on the website:")
    print(f"{Fore.YELLOW}1. SQL Injection")
    print(f"{Fore.YELLOW}2. Cross-Site Scripting (XSS)")
    print(f"{Fore.YELLOW}3. Clickjacking")
    print(f"{Fore.YELLOW}4. Man-in-the-Middle (MITM) Attacks")
    print(f"{Fore.YELLOW}5. Denial of Service (DoS)")

# Main function
def main():
    print(f"{Fore.CYAN}Welcome to the Vulnerability Scanner!\n")
    target = input(f"{Fore.CYAN}Enter the target (IP address or domain): {Style.RESET_ALL}")
    
    open_ports = scan_open_ports(target)
    if open_ports:
        print(f"\n{Fore.GREEN}Open ports on {target}: {open_ports}")
    else:
        print(f"\n{Fore.RED}No open ports found on {target}.")

    url = f"http://{target}"  
    check_outdated_software(url)
    detect_misconfigurations(url)
    display_possible_attacks()

if __name__ == "__main__":
    main()