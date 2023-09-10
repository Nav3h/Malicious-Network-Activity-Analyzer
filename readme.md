# Malicious Network Activity Analyzer

## Overview

The main idea and purpose of this Python project is to sniff network traffic on a given network interface (or all interfaces if none is specified) and scan the destination IP addresses of HTTP and HTTPS traffic for potential threats using three external APIs: Google Safe Browsing, VirusTotal, and AlienVault OTX.

## Libraries Used

The code uses the `scapy` library to sniff packets and the `requests` library to make HTTP requests to the external APIs.

## Functionality

The `process_packet` function processes each packet, checking if it contains an IP and TCP layer, and extracts the source and destination IP addresses. If the destination port is 80 or 443, it means that it's HTTP or HTTPS traffic, respectively. The destination IP address is then scanned using the `scan_ip_with_google`, `scan_ip_with_virustotal`, and `scan_ip_with_alienvault` functions.

## Rate Limiting and Exception Handling

The code also implements rate limiting to ensure that it does not exceed the rate limit for external API requests and includes exception handling for network connectivity problems.

## Usage

Provide instructions on how to use your project, including any required setup or configuration steps.

## Contributing

If you would like others to contribute to your project, provide instructions on how they can do so.

## License

Malicious Network Activity Analyzer
is licensed under the MIT License. You are permitted to use, copy, modify, distribute, sublicense and sell copies of the software.
