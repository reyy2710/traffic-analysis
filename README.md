

# Network Traffic Analysis for Security Monitoring

## Overview

This project involves analyzing real-time network traffic using Python scripts to detect suspicious activities and potential security threats. It leverages popular tools like Wireshark and Nmap to monitor network packets such as HTTP and DNS requests and identify vulnerabilities in the system.

## Features

* Real-time network traffic capture and analysis.
* Detection of suspicious patterns and anomalies.
* Use of Wireshark for packet capturing and inspection.
* Use of Nmap for network scanning and vulnerability detection.
* Reporting of detected vulnerabilities and suspicious activities.

## Built With

* Python 3
* Scapy (Python library for packet manipulation)
* Wireshark
* Nmap

## Getting Started

### Prerequisites

* Python 3 installed on your system.
* Wireshark installed (for capturing and analyzing packets).
* Nmap installed (for network scanning).
* Run with sufficient privileges to capture network packets (may require root/admin).

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/reyy2710/traffic-analysis.git
   cd traffic-analysis
   ```

2. Install Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the main script (may require sudo on Linux):

   ```bash
   sudo python3 traffic_analysis.py
   ```

## Usage

* The script captures live network traffic and inspects packets for suspicious activity.
* Use Wireshark separately for detailed packet inspection.
* Use Nmap commands to scan your network for vulnerabilities.

## Contribution

Feel free to fork the project and submit pull requests for improvements or bug fixes.



Project Link: [https://github.com/reyy2710/traffic-analysis](https://github.com/reyy2710/traffic-analysis)

