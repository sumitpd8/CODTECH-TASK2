Name: SUMIT PRASAD

Company: CODTECH IT SOLUTIONS

ID : CT8CSEH1724

Domain: Cyber Security & Ethical Hacking

Duration: July to August 2024

Mentor: Muzammil Ahmed


# Vulnerability Scanner

Vulnerability Scanner is a simple tool that scans a network or website for common security vulnerabilities such as open ports, outdated software versions, and misconfigurations. The tool uses Nmap for port scanning, requests for HTTP header inspection, and Colorama for colorful terminal output.

## Features

- Scans for open ports within the first 1024 ports.
- Checks for outdated software versions by inspecting HTTP response headers.
- Detects common misconfigurations in HTTP headers.
- Displays potential cyber attacks that the target might be vulnerable to.

## Requirements

- Python 3.x
- `nmap` library
- `requests` library
- `colorama` library
- Nmap tool installed on your system

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/Akashhorambe/CODTECH-Task2.git
    cd Vulnerability_Scanner
    ```

2. **Install the required Python libraries:**

    ```sh
    pip install python-nmap requests colorama
    ```

3. **Ensure Nmap is installed on your system:**

    - **Windows:** Download and install from the [Nmap website](https://nmap.org/download.html).
    - **Linux:** Use your package manager (e.g., `sudo apt-get install nmap` for Debian-based distributions).

## Usage

1. **Run the vulnerability scanner script:**

    ```sh
    python vulnerability_scanner.py
    ```

2. **Enter the target IP address or domain:**

    ```sh
    Enter the target (IP address or domain): scanme.nmap.org
    ```

3. **The tool will display open ports, outdated software versions, misconfigurations, and possible cyber attacks.**

## Example Output

```sh
Welcome to the Vulnerability Scanner!

Enter the target (IP address or domain): scanme.nmap.org

Scanning scanme.nmap.org for open ports...

Open ports on scanme.nmap.org: [22, 80]

Checking http://scanme.nmap.org for outdated software versions...

Response Headers: {'Server': 'Apache/2.4.7 (Ubuntu)', ...}
Server header: Apache/2.4.7 (Ubuntu)

Checking http://scanme.nmap.org for common misconfigurations...

Missing X-Frame-Options header. Possible Clickjacking attack vector.
Missing X-Content-Type-Options header. Possible MIME-sniffing attack vector.
Missing Content-Security-Policy header. Possible XSS attack vector.

Possible cyber attacks on the website:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Clickjacking
4. Man-in-the-Middle (MITM) Attacks
5. Denial of Service (DoS)
```
