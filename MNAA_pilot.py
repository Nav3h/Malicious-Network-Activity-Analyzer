from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from colorama import Fore, Style
from colorama import Fore
import time
import requests

"""
The main idea and purpose of the code is to sniff network traffic on a given network interface (or all interfaces if none is specified)
and scan the destination IP addresses of HTTP and HTTPS traffic for potential threats using three external APIs: 
Google Safe Browsing, VirusTotal, and AlienVault OTX.
The code uses the scapy library to sniff packets and the requests library to make HTTP requests to the external APIs.
The process_packet function processes each packet, checking if it contains an IP and TCP layer, and extracts the source and destination IP addresses.
If the destination port is 80 or 443, it means that its HTTP or HTTPS traffic, respectively.
The destination IP address is then scanned using the scan_ip_with_google, scan_ip_with_virustotal, and scan_ip_with_alienvault functions. 
The code also implements rate limiting to ensure that it does not exceed the rate limit for external API requests and includes exception handling for network connectivity problems.
"""


# Constants for colored output
GREEN = Fore.GREEN
RED = Fore.LIGHTRED_EX
BLACK = Fore.BLACK
RESET = Fore.RESET
BLUE = Fore.BLUE
CYAN = Fore.CYAN
LIGHTMAGENTA_EX = Fore.LIGHTMAGENTA_EX
YELLOW = Fore.YELLOW
# Rate limit for external API requests (requests per minute)
RATE_LIMIT_PER_MINUTE = 30  # Adjust as needed
# This variable is used to keep track of the time of the last request to an external API.
last_request_time = 0

# API keys and URLs for Google Safe Browsing, VirusTotal, and AlienVault OTX
GOOGLE_API_KEY = 'YOUR_GOOGLE_API_KEY'
GOOGLE_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'
VIRUSTOTAL_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY'
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
ALIENVAULT_API_KEY = 'YOUR_ALIENVAULT_API_KEY'
ALIENVAULT_API_URL = 'https://otx.alienvault.com/api/v1/indicators/IPv4/'
IPQUALITYSCORE_API_KEY = 'YOUR_IPQUALITYSCORE_API_KEY'
IPQUALITYSCORE_API_URL = 'https://www.ipqualityscore.com/api/json/ip/%s/%s'
IPQUALITYSCORE_SUSPICIOUS_SCORE = 75
IPQUALITYSCORE_HIGH_RISK_SCORE = 88


# Print banner and separator line
print(f"""{LIGHTMAGENTA_EX}
                                                           
  __  __       _ _      _                   _   _      _                      _                   _   _       _ _                                _                    
 |  \/  |     | (_)    (_)                 | \ | |    | |                    | |        /\       | | (_)     (_) |             /\               | |                   
 | \  / | __ _| |_  ___ _  ___  _   _ ___  |  \| | ___| |___      _____  _ __| | __    /  \   ___| |_ ___   ___| |_ _   _     /  \   _ __   __ _| |_   _ _______ _ __ 
 | |\/| |/ _` | | |/ __| |/ _ \| | | / __| | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /   / /\ \ / __| __| \ \ / / | __| | | |   / /\ \ | '_ \ / _` | | | | |_  / _ \ '__|
 | |  | | (_| | | | (__| | (_) | |_| \__ \ | |\  |  __/ |_ \ V  V / (_) | |  |   <   / ____ \ (__| |_| |\ V /| | |_| |_| |  / ____ \| | | | (_| | | |_| |/ /  __/ |   
 |_|  |_|\__,_|_|_|\___|_|\___/ \__,_|___/ |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ /_/    \_\___|\__|_| \_/ |_|\__|\__, | /_/    \_\_| |_|\__,_|_|\__, /___\___|_|   
                                                                                                                     __/ |                          __/ |             
                                                                                                                    |___/                          |___/                
{RESET}""")
print(f"""{YELLOW}                                          
___  ____ _  _          _  _ ____ _  _ ____ _  _    _  _ ____ ____ ____ _  _ _  _ ____ _   _ 
|  \ |___ |  |    __    |\ | |__| |  | |___ |__|    |__| |__| | __ [__  |__| |  | |__/  \_/  
|__/ |___  \/           | \| |  |  \/  |___ |  |    |  | |  | |__] ___] |  | |__| |  \   |                                                                                                                                                  
{RESET}""")
print(f"{BLUE}{'*-' * 85}{RESET}")


def rate_limit():
    # This function is used to limit the rate at which requests are sent to external APIs.
    global last_request_time
    current_time = time.time()
    # The function uses a global variable `last_request_time` to keep track of the time of the last request.
    if current_time - last_request_time < 60 / RATE_LIMIT_PER_MINUTE:
        # If the time between the current request and the last request is less than the allowed rate limit,
        # the function will sleep for the remaining time before sending the next request.
        time.sleep((60 / RATE_LIMIT_PER_MINUTE) - (current_time - last_request_time))
    last_request_time = current_time

def scan_ip_with_google(ip):
    # This function uses the Google Safe Browsing API to scan an IP address for potential threats.
    # It first calls the rate_limit function to ensure we are not exceeding our API rate limit.
    rate_limit()
    # The payload for the POST request to the Google Safe Browsing API is constructed.
    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["THREAT_TYPE_UNSPECIFIED", "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["PLATFORM_TYPE_UNSPECIFIED"],
            "threatEntryTypes": ["IP_RANGE"],
            "threatEntries": [{"ipRange": ip}]
        }
    }
    headers = {'Content-Type': 'application/json'}
    params = {'key': GOOGLE_API_KEY}
    try:
        # A POST request is made to the Google Safe Browsing API with the payload, headers, and API key.
        response = requests.post(GOOGLE_API_URL, headers=headers, params=params, json=payload)
        response_data = response.json()
        # The response from the API is then parsed to determine if any matches were found.
        if 'matches' in response_data:
            threat_types = set(match['threatType'] for match in response_data['matches'])
            if 'THREAT_TYPE_UNSPECIFIED' not in threat_types:
                # If matches were found and the threat type is not unspecified, it means that the IP address is potentially dangerous.
                return f"{RED}[!] WARNING: The IP address '{ip}' is potentially dangerous according to Google Safe Browsing.{RESET}"
            else:
                # If matches were found but the threat type is unspecified, it means that the IP address is safe.
                return f"{GREEN}[+] The IP address '{ip}' is safe according to Google Safe Browsing.{RESET}"
        else:
            # If no matches were found, it means that the IP address is safe.
            return f"{GREEN}[+] The IP address '{ip}' is safe according to Google Safe Browsing.{RESET}"

    except requests.exceptions.RequestException as e:
        # Handle network errors
        return f"{BLACK}[-] Error scanning {ip} with Google Safe Browsing: Network error: {str(e)}{RESET}"
    except ValueError as e:
        # Handle JSON parsing errors
        return f"{BLACK}[-] Error scanning {ip} with Google Safe Browsing: JSON parsing error: {str(e)}{RESET}"
    except Exception as e:
        # Handle other exceptions
        if 'code' in str(e) and 'message' in str(e):
            # Handle API errors (e.g., invalid API key or URL, rate limit exceeded)
            error = eval(str(e))
            return f"{BLACK}[-] Error scanning {ip} with Google Safe Browsing: API error: {error['message']} (code: {error['code']}){RESET}"
        else:
            return f"{BLACK}[-] Error scanning {ip} with Google Safe Browsing: {str(e)}{RESET}"

def scan_ip_with_virustotal(ip):
    # This function uses the VirusTotal API to scan an IP address for potential threats.
    # It first calls the rate_limit function to ensure we are not exceeding our API rate limit.
    rate_limit()
    params = {'apikey': VIRUSTOTAL_API_KEY, 'ip': ip}
    try:
        # A GET request is made to the VirusTotal API with the IP address and the API key.
        response = requests.get(VIRUSTOTAL_API_URL, params=params)
        response_data = response.json()
        # The response from the API is then parsed to determine if any detected URLs were found.
        if 'detected_urls' in response_data:
            if len(response_data['detected_urls']) > 0:
                # If detected URLs were found, it means that the IP address is potentially dangerous.
                return f"{RED}[!] WARNING: The IP address '{ip}' is potentially dangerous according to VirusTotal.{RESET}"
            else:
                # If no detected URLs were found, it means that the IP address is safe.
                return f"{GREEN}[+] The IP address '{ip}' is safe according to VirusTotal.{RESET}"
        else:
            return f"{GREEN}[+] The IP address '{ip}' is safe according to VirusTotal.{RESET}"

    except requests.exceptions.RequestException as e:
        # Handle network errors
        return f"{BLACK}[-] Error scanning {ip} with VirusTotal: Network error: (API at requests limit).{RESET}"
    except ValueError as e:
        # Handle JSON parsing errors
        return f"{BLACK}[-] Error scanning {ip} with VirusTotal: JSON parsing error: {str(e)}{RESET}"
    except Exception as e:
        # Handle other exceptions
        if 'code' in str(e) and 'message' in str(e):
            # Handle API errors (e.g., invalid API key or URL, rate limit exceeded)
            error = eval(str(e))
            return f"{BLACK}[-] Error scanning {ip} with VirusTotal: API error: {error['message']} (code: {error['code']}){RESET}"
        else:
            return f"{BLACK}[-] Error scanning {ip} with VirusTotal: {str(e)}{RESET}"

def scan_ip_with_alienvault(ip):
    # This function uses the AlienVault OTX API to scan an IP address for potential threats.
    # It first calls the rate_limit function to ensure we are not exceeding our API rate limit.
    rate_limit()
    headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
    try:
        # A GET request is made to the AlienVault OTX API with the IP address and the API key.
        response = requests.get(f'{ALIENVAULT_API_URL}{ip}', headers=headers)
        response_data = response.json()
        # The response from the API is then parsed to determine if any pulses were found.
        if 'pulse_info' in response_data:
            if response_data['pulse_info']['count'] > 0:
                # If pulses were found, it means that the IP address is potentially dangerous.
                return f"{RED}[!] WARNING: The IP address '{ip}' is potentially dangerous according to AlienVault OTX.{RESET}"
            else:
                # If no pulses were found, it means that the IP address is safe.
                return f"{GREEN}[+] The IP address '{ip}' is safe according to AlienVault OTX.{RESET}"
        else:
            return f"{GREEN}[+] The IP address '{ip}' is safe according to AlienVault OTX.{RESET}"

    except requests.exceptions.RequestException as e:
        # Handle network errors
        return f"{BLACK}[-] Error scanning {ip} with AlienVault OTX: Network error: {str(e)}{RESET}"
    except ValueError as e:
        # Handle JSON parsing errors
        return f"{BLACK}[-] Error scanning {ip} with AlienVault OTX: JSON parsing error: {str(e)}{RESET}"
    except Exception as e:
        # Handle other exceptions
        if 'code' in str(e) and 'message' in str(e):
            # Handle API errors (e.g., invalid API key or URL, rate limit exceeded)
            error = eval(str(e))
            return f"{BLACK}[-] Error scanning {ip} with AlienVault OTX: API error: {error['message']} (code: {error['code']}){RESET}"
        else:
            return f"{BLACK}[-] Error scanning {ip} with AlienVault OTX: {str(e)}{RESET}"

def scan_ip_with_ipqualityscore(ip):
    url_request = f"https://www.ipqualityscore.com/api/json/ip/{IPQUALITYSCORE_API_KEY}/{ip}"
    params = {'key': IPQUALITYSCORE_API_KEY, 'ip': ip}
    response = requests.get(url_request, params=params)
    response_data = response.json()
    if 'success' in response_data and response_data['success'] == True:
        if response_data['fraud_score'] >= IPQUALITYSCORE_SUSPICIOUS_SCORE:
            return f"{RED}[!] WARNING: The IP address '{ip}' is potentially dangerous according to ipqualityscore.{RESET}"
        else:
            return f"{GREEN}[+] The IP address '{ip}' is safe according to ipqualityscore.{RESET}"
    else:
        return f"{BLACK}[-] Error scanning {ip} with ipqualityscore: Network error: (API at requests limit).{RESET}"


def sniff_packets(iface=None):
    # This function sniffs packets on a given interface (or all interfaces if none is specified) and processes each packet.
    if iface:
        sniff(filter="port 80 or port 443", prn=process_packet, iface=iface, store=False)
    else:
        sniff(filter="port 80 or port 443", prn=process_packet, store=False)

def process_packet(packet):
    # This function processes each packet, checking if it contains an IP and TCP layer.
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet[TCP].dport == 80:
            # If the destination port is 80, it means that it's HTTP traffic.
            if dst_ip not in printed_ips:
                print(f"{GREEN}Detected HTTP traffic: (src){src_ip} ---> (dst){dst_ip}{RESET}")
                print(scan_ip_with_google(dst_ip))
                print(scan_ip_with_virustotal(dst_ip))
                print(scan_ip_with_alienvault(dst_ip))
                print(scan_ip_with_ipqualityscore(dst_ip))
                print(f"{BLUE}{'*-' * 40}{RESET}")
                print(f'{CYAN}-{RESET}' * 80)
                print(f"{BLUE}{'*-' * 40}{RESET}")
                printed_ips.add(dst_ip)
        elif packet[TCP].dport == 443:
            # If the destination port is 443, it means that it's HTTPS traffic.
            if dst_ip not in printed_ips:
                print(f"{GREEN}Detected HTTPS traffic: (src){src_ip} ---> (dst){dst_ip}{RESET}")
                print(scan_ip_with_google(dst_ip))
                print(scan_ip_with_virustotal(dst_ip))
                print(scan_ip_with_alienvault(dst_ip))
                print(f"{BLUE}{'*-' * 40}{RESET}")
                print(f'{CYAN}-{RESET}' * 80)
                print(f"{BLUE}{'*-' * 40}{RESET}")
                printed_ips.add(dst_ip)

# This set is used to keep track of IP addresses that have already been printed.
printed_ips = set()

try:
    # Sniff packets
    sniff_packets()
except OSError as e:
    # Handle network connectivity problems
    print(f"{RED}[-] Error: Network connectivity problem: {str(e)}{RESET}")