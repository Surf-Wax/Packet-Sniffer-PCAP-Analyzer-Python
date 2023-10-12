# Packet Sniffer and Processor in Python

This repository contains two Python scripts for both capturing network traffic `Sniffer.py` and analyzing it `PCAP_Processor.py`.

## Sniffer

### Description

`Sniffer.py` is a Python script for network packet sniffing, specifically capturing and analyzing IP packets. It uses a raw socket to capture network traffic and extracts information about each observed packet, such as the source and destination IP addresses and the protocol used. The captured data is then organized and displayed in a tabular format using the PrettyTable library.

The script allows you to monitor network traffic and count the occurrences of unique combinations of source and destination IP addresses along with the associated protocol.

### Usage

1. Install the required python libraries using pip

   ```bash
   pip install ipaddress
   ```
   ```bash
   pip install prettytable
   ```

3. Run the script as sudo using Python3:

   ```bash
   sudo python3 Sniffer.py
   ```
   
4. Wait for the script to capture packets

5. Observe the captured data


## PCAP_Processor

### Description

`PCAP_Processor` is a Python script designed to analyze a standard PCAP file (Packet Capture) and create a passive asset map based on the unique network activity observed in the capture. The resulting asset map is stored as a serialized Python object. Additionally, the script generates an HTML file that visually represents the observed asset map.

### How it works

The script extracts information from the PCAP file, including Ethernet frames, IP addresses, transport protocols (TCP, UDP, ICMP), and ports.
It uses lookup tables to identify information about MAC addresses (e.g., manufacturer), transport protocols, and port numbers.
The script builds an asset map that contains information about the source and destination IP addresses, protocols, MAC addresses, port numbers, TTL (Time To Live), and more.
This information is organized into PrettyTable objects for easy viewing and analysis.
The script writes the asset map tables to text files in the "Reports" directory.
The HTML file is generated to provide a visual representation of the observed network activity.

### Usage

1. Install the required python libraries using pip

   ```bash
   pip install pypcapfile
   ```
   ```bash
   pip install prettytable
   ```
   ```bash
   pip install pickle
   ```

3. Run the script as sudo using Python3

   ```bash
   sudo python3 PCAP_Processor.py
   ```
   
5. Observed the Processed Data
