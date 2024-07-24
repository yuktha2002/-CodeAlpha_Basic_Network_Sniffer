
# Basic Network Sniffer

## Overview
This project is a basic network sniffer built using Python and the Scapy library. The aim of the project is to capture and analyze network traffic, allowing you to understand how data flows on a network and how network packets are structured.

## Features
- Capture packets on a specified network interface.
- Save captured packets to a PCAP file for later analysis.
- Optionally analyze HTTP and TCP streams from the captured packets.

## Prerequisites
- Python 3.x
- Scapy (install via `pip install scapy`)

## Usage
1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/basic-network-sniffer.git
    cd basic-network-sniffer
    ```

2. Run the Python script with appropriate arguments. Below are some examples:

    - Capture packets on the `wlan0` interface and save them to `capture.pcap`:
      ```bash
      python network_sniffer.py -i wlan0 -o capture.pcap
      ```

    - Capture packets and analyze HTTP streams:
      ```bash
      python network_sniffer.py -i wlan0 -o capture.pcap -H
      ```

    - Capture packets and analyze TCP streams:
      ```bash
      python network_sniffer.py -i wlan0 -o capture.pcap -T
      ```

## Command Line Arguments
- `-i`, `--interface`: Specify the network interface to sniff on (e.g., `eth0`, `wlan0`).
- `-o`, `--output`: Specify the output PCAP file for saving the captured packets.
- `-H`, `--http-stream`: Analyze HTTP streams captured during sniffing.
- `-T`, `--tcp-stream`: Analyze TCP streams captured during sniffing.

## Output
- **HTTP Streams:** Lists connections where HTTP traffic was detected, showing source and destination IPs.
- **TCP Streams:** Displays all TCP connections with source and destination IPs and ports.

Example output for HTTP streams analysis:
```
HTTP Streams:
  192.168.1.2 -> 93.184.216.34 : 80
```

Example output for TCP streams analysis:
```
TCP Streams:
  192.168.1.2:54321 -> 93.184.216.34:80
```

## Code Explanation
The main script performs the following tasks:
1. Parses command-line arguments to get the interface, output file, and options for HTTP/TCP analysis.
2. Uses Scapy's `sniff` function to capture packets on the specified interface.
3. Saves the captured packets to a PCAP file using `wrpcap`.
4. Optionally analyzes HTTP and TCP streams from the captured packets and prints the results.

Here's a brief code summary:
```python
from scapy.all import sniff, TCP, UDP, ICMP, IP, wrpcap
import argparse

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer")
    # Argument parsing code here...

    packets = sniff(iface=iface, count=1000)
    wrpcap(output_file, packets)

    # HTTP streams analysis code here...

    # TCP streams analysis code here...

if __name__ == "__main__":
    main()
```

## Contribution
Contributions are welcome! Please fork this repository and submit a pull request for any improvements or bug fixes. 

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

