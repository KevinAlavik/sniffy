import argparse
import sys
import os
import netifaces
from scapy.all import *
from loguru import logger

def setup_logging(log_file=None, debug=False):
    logger.remove()
    
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        " - "
        "<level>{message}</level>"
    )
    
    log_level = "DEBUG" if debug else "INFO"
    
    
    logger.add(sys.stdout, format=log_format, level=log_level)
    
    if log_file:
        
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        
        logger.add(log_file, format=log_format, level=log_level, rotation="1 week", retention="1 month")

def parse_arguments():
    parser = argparse.ArgumentParser(description="Advanced IP packet sniffer with enhanced features.")
    parser.add_argument("target_ip", help="The IP address of the target to sniff.")
    parser.add_argument("--interface", help="Network interface to sniff on.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging for debugging.")
    parser.add_argument("--timeout", type=int, default=60, help="Duration to sniff in seconds. Default is 60 seconds.")
    parser.add_argument("--filter", help="Custom BPF filter for packets. E.g., 'tcp', 'udp', 'port 80'")
    parser.add_argument("--logfile", help="File to write logs to. If not provided, logs will be printed to console.")
    parser.add_argument("--show-dns", action="store_true", help="Show DNS details if present.")
    parser.add_argument("--packet-count", type=int, default=-1, help="Number of packets to capture. Default is unlimited.")
    parser.add_argument("--protocol", choices=['tcp', 'udp', 'icmp'], help="Filter packets by protocol.")
    return parser.parse_args()

def protocol_name(proto: int) -> str:
    protocol_map = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP'
    }
    return protocol_map.get(proto, f'Unknown ({proto})')

def log_packet_info(logger, packet_type: str, ip_layer: IP, packet_length: int):
    logger.info(
        f"TYPE: {packet_type:8} FROM: {ip_layer.src:15} -> TO: {ip_layer.dst:15} "
        f"PROTOCOL: {protocol_name(ip_layer.proto):7} LENGTH: {packet_length:5} bytes"
    )

def log_detailed_info(logger, packet, args):
    try:
        if args.verbose:
            ip_layer = packet[IP]
            
            protocol_str = protocol_name(ip_layer.proto)
            protocol_width = len(protocol_str) + 2
            length_width = len(str(len(packet))) + 2
            ip_width = max(len(ip_layer.src or ''), len(ip_layer.dst or '')) + 2
            
            tcp_sport_len = len(str(packet[TCP].sport)) if packet.haslayer(TCP) and packet[TCP].sport is not None else 2
            tcp_dport_len = len(str(packet[TCP].dport)) if packet.haslayer(TCP) and packet[TCP].dport is not None else 2
            udp_sport_len = len(str(packet[UDP].sport)) if packet.haslayer(UDP) and packet[UDP].sport is not None else 2
            udp_dport_len = len(str(packet[UDP].dport)) if packet.haslayer(UDP) and packet[UDP].dport is not None else 2
            port_width = max(tcp_sport_len, tcp_dport_len, udp_sport_len, udp_dport_len) + 2
            
            tcp_chksum_len = len(str(packet[TCP].chksum)) if packet.haslayer(TCP) and packet[TCP].chksum is not None else 4
            udp_chksum_len = len(str(packet[UDP].chksum)) if packet.haslayer(UDP) and packet[UDP].chksum is not None else 4
            icmp_chksum_len = len(str(packet[ICMP].chksum)) if packet.haslayer(ICMP) and packet[ICMP].chksum is not None else 4
            checksum_width = max(tcp_chksum_len, udp_chksum_len, icmp_chksum_len) + 2
            
            tcp_seq_len = len(str(packet[TCP].seq)) if packet.haslayer(TCP) and packet[TCP].seq is not None else 10
            tcp_ack_len = len(str(packet[TCP].ack)) if packet.haslayer(TCP) and packet[TCP].ack is not None else 10
            seq_ack_width = max(tcp_seq_len, tcp_ack_len) + 2

            logger.debug(f"  Protocol:             {protocol_str:<{protocol_width}}")
            logger.debug(f"  Length:               {len(packet):>{length_width}} bytes")
            logger.debug(f"  Source IP:            {ip_layer.src:<{ip_width}}")
            logger.debug(f"  Destination IP:       {ip_layer.dst:<{ip_width}}")

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                flags = str(tcp_layer.flags)
                logger.debug(f"  Source Port:          {tcp_layer.sport:>{port_width}}")
                logger.debug(f"  Destination Port:     {tcp_layer.dport:>{port_width}}")
                logger.debug(f"  Flags:                {flags:<{port_width}}")
                logger.debug(f"  Window Size:          {tcp_layer.window:>{port_width}}")
                logger.debug(f"  Checksum:             {tcp_layer.chksum:>{checksum_width}}")
                logger.debug(f"  Sequence Number:      {tcp_layer.seq:>{seq_ack_width}}")
                logger.debug(f"  Acknowledgment Number:{tcp_layer.ack:>{seq_ack_width}}")

            if packet.haslayer(UDP):
                udp_layer = packet[UDP]
                logger.debug(f"  Source Port:          {udp_layer.sport:>{port_width}}")
                logger.debug(f"  Destination Port:     {udp_layer.dport:>{port_width}}")
                logger.debug(f"  Length:               {udp_layer.len:>{length_width}}")
                logger.debug(f"  Checksum:             {udp_layer.chksum:>{checksum_width}}")

            if packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                logger.debug(f"  Type:                 {icmp_layer.type:<{protocol_width}}")
                logger.debug(f"  Code:                 {icmp_layer.code:<{protocol_width}}")
                logger.debug(f"  Checksum:             {icmp_layer.chksum:>{checksum_width}}")

            if packet.haslayer(Raw):
                raw_layer = packet[Raw]
                payload = raw_layer.load
                logger.debug(f"  Payload Length:       {len(payload)} bytes")
                logger.debug(f"  Payload Sample:       {payload[:20].hex()}...")  
    except Exception as e:
        logger.error(f"Error in log_detailed_info: {e}")

def process_packet(packet, target_ip: str, local_ip: str, logger, show_dns: bool, args):
    try:
        if IP in packet:
            ip_layer = packet[IP]
            if ip_layer.src == target_ip or ip_layer.dst == target_ip:
                if ip_layer.src != local_ip and ip_layer.dst != local_ip:
                    packet_type = "SENT" if ip_layer.src == target_ip else "RECEIVED"
                    log_packet_info(logger, packet_type, ip_layer, len(packet))
                    
                    if args.verbose:
                        log_detailed_info(logger, packet, args)

                    if show_dns and packet.haslayer(DNS):
                        dns_layer = packet[DNS]
                        logger.debug(
                            f"  DNS Query:            {dns_layer.qd.qname.decode(errors='ignore')}"
                        )
    except Exception as e:
        logger.error(f"Error in process_packet: {e}")

def main():
    args = parse_arguments()
    setup_logging(log_file=args.logfile, debug=args.verbose)
    
    logger.info("Sniffy: A simple IP sniffer. Made by Kevin Alavik")

    local_ip = None
    try:
        if args.interface:
            addrs = netifaces.ifaddresses(args.interface)
            if netifaces.AF_INET not in addrs:
                logger.error(f"Error: {args.interface} does not have an IPv4 address.")
                sys.exit(1)
            local_ip = addrs[netifaces.AF_INET][0]["addr"]
            if local_ip != args.target_ip:
                logger.info(f"Using interface {args.interface} with IP address {local_ip}")
        else:
            logger.info("No specific network interface provided; using default.")
            local_ip = netifaces.ifaddresses(netifaces.interfaces()[0])[netifaces.AF_INET][0]["addr"]
    except Exception as e:
        logger.error(f"Error retrieving local IP address: {e}")
        sys.exit(1)

    sniff_filter = args.filter or ""
    if args.protocol:
        sniff_filter += f" and {args.protocol}"

    try:
        sniff(
            iface=args.interface,
            filter=sniff_filter,
            prn=lambda pkt: process_packet(pkt, args.target_ip, local_ip, logger, args.show_dns, args),
            timeout=args.timeout,
            count=args.packet_count
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        logger.error(f"Exception details: {sys.exc_info()}")
        sys.exit(1)

if __name__ == "__main__":
    main()
