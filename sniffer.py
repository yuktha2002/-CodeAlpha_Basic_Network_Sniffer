from scapy.all import sniff, TCP, UDP, ICMP, IP, wrpcap
import argparse

def main():
    parser = argparse.ArgumentParser(description="Packet sniffer")
    parser.add_argument("-i", "--interface", help="Interface to sniff on (e.g. eth0, wlan0)")
    parser.add_argument("-o", "--output", help="Output PCAP file")
    parser.add_argument("-H", "--http-stream", action="store_true", help="Analyze HTTP streams")
    parser.add_argument("-T", "--tcp-stream", action="store_true", help="Analyze TCP streams")
    args = parser.parse_args()

    if args.interface:
        iface = args.interface
    else:
        iface = None

    if args.output:
        output_file = args.output
    else:
        output_file = "capture.pcap"

    packets = sniff(iface=iface, count=1000)

    try:
        wrpcap(output_file, packets)
    except Exception as e:
        print(f"Error writing packets to file: {e}")

    if args.http_stream:
        http_streams = []
        for packet in packets:
            if packet.haslayer(TCP) and packet.dport == 80:
                http_streams.append(packet)
        print("HTTP Streams:")
        for stream in http_streams:
            print(f"  {stream[IP].src} -> {stream[IP].dst} : {stream[TCP].dport}")

    if args.tcp_stream:
        tcp_streams = {}
        for packet in packets:
            if packet.haslayer(TCP):
                key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
                if key not in tcp_streams:
                    tcp_streams[key] = []
                tcp_streams[key].append(packet)
        print("TCP Streams:")
        for key, stream in tcp_streams.items():
            print(f"  {key[0]}:{key[2]} -> {key[1]}:{key[3]}")

if __name__ == "__main__":
    main()